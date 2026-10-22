#define main prior_pipeline_main
#include "tests_ntasm_machine_pipeline.c"
#undef main
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include <sys/stat.h>

/* THE MULTI-SOURCE PIPELINE GATE.
 *
 * The producer is the Nova module itself: `nova_machine_many` and
 * `tests/nova-machine-many-entry.nova`. The harness compiles ONLY that
 * producer, hands it SEVERAL Nova sources in one blob with their spans, and
 * then EXECUTES the PE it produced on the real ABI2 runtime.
 *
 * The sources of a fixture are SEPARATE strings. The harness copies them into
 * one blob and publishes the spans, because `parse_many` takes a blob and a
 * span table; no source is renamed, no module is simulated by a
 * concatenation, and no C rewrites a fixture.
 *
 * The independent oracle is TWO-FOLD and neither part is the producer: the C
 * reference's own multi-source checker says whether the sources are
 * acceptable at all, and the PE that comes out is executed for real.
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
        uintptr_t lo = (uintptr_t)(img + va) & ~(uintptr_t)4095, hi = (uintptr_t)(img + va + vs); /* the PAGE mask: 4095 clears the low twelve bits. 4096 would clear ONE bit only, so the range would start inside the text's own page and the later mprotect would strip EXEC from the text. */
        int prot = PROT_READ | (ch & 0x80000000u ? PROT_WRITE : 0) | (ch & 0x20000000u ? PROT_EXEC : 0);
        if (vs && mprotect((void *)lo, hi - lo, prot)) REFUSE("mprotect section %u: %s", i, strerror(errno));
    }
    mapped_out->base=img;mapped_out->size=size_image;mapped_out->entry=img+entry;
    return 0;
#undef REFUSE
}

typedef uint64_t (__attribute__((ms_abi)) *Abi2Entry)(NovaContextV2*,const uint64_t*,uint64_t);
static unsigned abi_native;

/* THE SIZES THE MANY PIPELINE NEEDS. The node, scope, bind, field and module
 * tables are the frontend's own. The module table holds the unit table (nine
 * words per source) FOLLOWED BY the catalog (five words per top level
 * declaration), so it is the largest of them. */
#define MANY_NODES 65536
#define MANY_SIDES 4096
#define MANY_BINDS 8192
#define MANY_FIELDS 8192
#define MANY_MODULES 8192
#define MANY_MIR 65536
#define MANY_PE 65536
#define MANY_BLOB 65536
#define MANY_REPORT 14
#define MANY_DECLS 65536

/* THE TWO CAP SETS, AND WHY THERE ARE TWO.
 *
 * The small fixtures keep the caps they had: a small row measured with a big
 * budget says nothing about the small path, and a budget that grows with the
 * row is not a budget.
 *
 * The audit's caps are the big profile's, and the MIR one is the RUNTIME'S OWN
 * CEILING EXACTLY: BYTES_MAX is 64MiB (runtime_v2.c:9) and 8388608 words of
 * u64 IS 64MiB, so the audit borrows the largest buffer the runtime allows and
 * NOTHING in the runtime is raised to make it fit. BUFFER_MAX (65536 live
 * buffers) and the 256MiB owned ceiling are likewise left alone: a bound that
 * stops the closure is MEASURED, not widened.
 */
struct Caps {
  uint64_t nodes, sides, binds, fields, modules; /* words */
  uint64_t mir, pe, blob, decls;                 /* bytes */
};
#define AUDIT_BLOB    (4u*1024u*1024u)
#define AUDIT_NODES   4194304u
#define AUDIT_SIDES   65536u
#define AUDIT_BINDS   262144u
#define AUDIT_FIELDS  65536u
#define AUDIT_MODULES 32768u
#define AUDIT_MIR     8388608u
#define AUDIT_PE      (16u*1024u*1024u)
#define AUDIT_DECLS   (1u*1024u*1024u)
#define AUDIT_SOURCES 64
static const struct Caps SMALL_CAPS = { MANY_NODES, MANY_SIDES, MANY_BINDS, MANY_FIELDS, MANY_MODULES,
                                       MANY_MIR, MANY_PE, MANY_BLOB, MANY_DECLS };
static const struct Caps AUDIT_CAPS = { AUDIT_NODES, AUDIT_SIDES, AUDIT_BINDS, AUDIT_FIELDS, AUDIT_MODULES,
                                       AUDIT_MIR, AUDIT_PE, AUDIT_BLOB, AUDIT_DECLS };

/* THE LENGTHS BUFFER, twelve words: [0] the PE's bytes, which the object stage
 * writes, [1] the declarations' bytes, [2] the MIR image's used bytes, [3]
 * the frontend's node count, [4] its scope count, [5] its bind count, [6] the
 * image builder's capacity code. The object stage CLEARS the report, so the
 * frontend's counts cannot survive there: the entry publishes them here
 * instead, and the report keeps the one meaning it has, which is the stage.
 * The capacity code is published so this gate pins the EXACT refusal of a
 * full image without holding a literal of its own. [7] the functions the
 * program declares, [8] the ones the root module's main can reach, [9] the
 * declarations the emitted unit carries, and [10] the functions THIS object
 * defines: they are the CLOSED MODE's and the BATCH's measurement, they are
 * read before the emission stage clears the report, and they are zero in the
 * normal mode, whose report keeps the meaning it had. */
#define MANY_LENGTHS 12
/* THE LOWER'S OWN E_AST, which is the CONSEQUENCE this gate must NOT see when
 * the image is full: the builder refuses first and the lower's own shape
 * check is what it runs into afterwards. Its derivation is named:
 * nova_machine_lower.E_AST. */
#define MANY_E_AST 971
/* A CAPACITY FAR BELOW WHAT THE PROGRAM NEEDS, so the image builder fills it
 * and refuses. The number is not a record count and does not pretend to be
 * one: it only has to be too small, and it is the SAME capacity the full
 * profile already measures with, so the two runs are comparable. */
#define MANY_TINY_MIR 1600

/* A FIXTURE: the sources as they are written, the root index, and what the
 * produced PE must answer. `refused` means the PIPELINE must refuse the
 * sources, and the C reference must refuse them too. */
struct Fixture {
  const char *const *sources;
  unsigned count;
  unsigned root;
  uint64_t want;   /* the PE's answer */
  uint64_t error;  /* the runtime error the PE must report */
  int refused;     /* 1: the sources must be refused */
  int oracle;      /* 1: the C reference has a verdict on these sources */
};

/* TWO MODULES, ONE EXPORTED CALL. */
static const char *const fx_two_modules[] = {
  "module app;\nimport lib;\nexport fn main() -> u64 { return lib.answer(); }\n",
  "module lib;\nexport fn answer() -> u64 { return 42; }\n"
};
/* THE SAME PRIVATE NAME IN TWO MODULES. */
static const char *const fx_private_names[] = {
  "module mod_a;\nimport mod_b;\nfn helper() -> u64 { return 20; }\nexport fn main() -> u64 { return helper() + mod_b.calc(); }\n",
  "module mod_b;\nfn helper() -> u64 { return 22; }\nexport fn calc() -> u64 { return helper(); }\n"
};
/* TWO FILES OF THE SAME MODULE. */
static const char *const fx_two_files[] = {
  "module app;\nimport lib;\nexport fn main() -> u64 { return lib.answer(); }\n",
  "module app;\nfn helper() -> u64 { return 41; }\n",
  "module lib;\nexport fn answer() -> u64 { return 42; }\n"
};
/* AN IMPORT CYCLE WITH FINITE CALLS. */
static const char *const fx_cycle[] = {
  "module x;\nimport y;\nexport fn main() -> u64 { return y.down(3); }\n",
  "module y;\nimport x;\nexport fn down(n: u64) -> u64 { if n == 0 { return 42; } return x.half(n); }\n",
  "module x;\nimport y;\nexport fn half(n: u64) -> u64 { return y.down(n - 1); }\n"
};
/* AN EXPORTED RECORD AND A BUFFER PASSED BETWEEN MODULES. The record is read
 * where it is declared, so no qualified type spelling is needed, and the
 * buffer crosses the module boundary as an argument. */
static const char *const fx_record_buffer[] = {
  "module app;\nimport lib;\nexport fn main() -> u64 { let b: buf<u8> = alloc(runtime(), 2); return lib.total(b); }\n",
  "module lib;\nexport struct Item { value: u64 }\nexport fn make() -> Item { return Item{value: 40}; }\nexport fn total(b: buf<u8>) -> u64 { let p: Item = make(); return p.value + len(b); }\n"
};
/* THIRTEEN FUNCTIONS IN ONE MODULE: the ordinals and the names go past nine.
 * They are PRIVATE, so the private naming path is the one exercised. */
static const char *const fx_twelve[] = {
  "module many;\nexport fn main() -> u64 { return f00() + f01() + f02() + f03() + f04() + f05() + f06() + f07() + f08() + f09() + f10() + f11(); }\n"
  "fn f00() -> u64 { return 1; }\nfn f01() -> u64 { return 1; }\nfn f02() -> u64 { return 1; }\n"
  "fn f03() -> u64 { return 1; }\nfn f04() -> u64 { return 1; }\nfn f05() -> u64 { return 1; }\n"
  "fn f06() -> u64 { return 1; }\nfn f07() -> u64 { return 1; }\nfn f08() -> u64 { return 1; }\n"
  "fn f09() -> u64 { return 1; }\nfn f10() -> u64 { return 1; }\nfn f11() -> u64 { return 1; }\n"
};
/* A MUTABLE BUFFER REASSIGNED, AND A BUFFER RETURNED BY A PRIVATE FUNCTION.
 * The allocation is bound to a NAME first: the point of the row is the
 * REASSIGNMENT of a buffer binding, not an allocation written in an
 * assignment, and the expected answer stays seven (five plus two). */
static const char *const fx_mutable[] = {
  "module app;\nfn make() -> buf<u8> { let b: buf<u8> = alloc(runtime(), 2); return b; }\n"
  "export fn main() -> u64 { let mut b: buf<u8> = alloc(runtime(), 2); let bigger: buf<u8> = alloc(runtime(), 5); b = bigger; let c: buf<u8> = make(); return len(b) + len(c); }\n"
};
/* A MISSING IMPORT. */
static const char *const fx_missing_import[] = {
  "module app;\nimport nosuch;\nexport fn main() -> u64 { return 1; }\n"
};
/* A CALL INTO ANOTHER MODULE'S PRIVATE FUNCTION. */
static const char *const fx_private_access[] = {
  "module app;\nimport lib;\nexport fn main() -> u64 { return lib.hidden(); }\n",
  "module lib;\nfn hidden() -> u64 { return 42; }\nexport fn open() -> u64 { return 42; }\n"
};
/* A DIAMOND: THE APPLICATION CALLS TWO MODULES AND BOTH CALL THE SAME THIRD
 * ONE. The shared module is reached by two paths, so the closed mode must
 * keep it, and it must keep it ONCE. The C reference has no verdict claimed
 * here: the PE's own answer is the oracle. */
static const char *const fx_diamond[] = {
  "module app;\nimport left;\nimport right;\nexport fn main() -> u64 { return left.value() + right.value(); }\n",
  "module left;\nimport base;\nfn helper() -> u64 { return 40; }\nexport fn value() -> u64 { return helper() + base.one(); }\n",
  "module right;\nimport base;\nfn helper() -> u64 { return 2; }\nexport fn value() -> u64 { return helper() + base.one(); }\n",
  "module base;\nexport fn one() -> u64 { return 0; }\n"
};
/* A CALL TO A FUNCTION DECLARED LATER IN THE SAME SOURCE. The call is
 * resolved by the ordinal and not by the position, so the declaration order
 * in the source is not the call order. */
static const char *const fx_forward[] = {
  "module app;\nexport fn main() -> u64 { return later(); }\nfn later() -> u64 { return 42; }\n"
};

/* THE ROOT SELECTION'S THREE ANSWERS. The C REFERENCE HAS NO ROOT PARAMETER
 * AND SAYS NOTHING ABOUT A MAIN, so these rows carry an EXPLICIT oracle --
 * the refusal is the root selection's own code -- and no C verdict is
 * consulted for them. */
static const char *const fx_no_main[] = {
  "module app;\nexport fn other() -> u64 { return 1; }\n"
};
static const char *const fx_two_mains[] = {
  "module app;\nexport fn main() -> u64 { return 1; }\n",
  "module lib;\nexport fn main() -> u64 { return 2; }\n"
};
static const char *const fx_main_elsewhere[] = {
  "module app;\nimport lib;\nexport fn other() -> u64 { return 1; }\n",
  "module lib;\nexport fn main() -> u64 { return 42; }\n"
};
/* A MUTABLE BOOL COMPARED WITH A LITERAL.
 *
 * A MUTABLE BOOL LIVES IN A CELL of eight bits, and the literals true and
 * false and the type bool are ONE bit, so a comparison between the two
 * compares two widths. The compiler's own sources hold `while done==false`
 * -- the driver's diag_number is one -- so this is the shape the
 * reconstruction meets.
 *
 * THE ANSWERS BELOW ARE EXECUTED, not asserted: the produced PE must answer
 * 42 or 43, and a refusal is a failure and not an answer. */
static const char *const fx_bool_cmp_false[] = {
  "module app;\nexport fn main() -> u64 { let mut b: bool = true; if b == false { return 0; } return 42; }\n"
};
/* THE SAME BOOL, REASSIGNED, COMPARED WITH THE OTHER LITERAL. */
static const char *const fx_bool_cmp_true[] = {
  "module app;\nexport fn main() -> u64 { let mut b: bool = false; b = true; if b == true { return 43; } return 0; }\n"
};
/* THE LOOP THE COMPILER'S OWN CODE WRITES. */
static const char *const fx_bool_loop[] = {
  "module app;\nexport fn main() -> u64 { let mut done: bool = false; let mut x: u64 = 0; while done == false { x = 42; done = true; } return x; }\n"
};
/* THE SAME BOOL PASSED TO A FUNCTION AND COMPARED THERE. The comparison and
 * the direct call are two different questions, and this row is the second
 * one: a bool argument crosses the call by value and the callee returns it. */
static const char *const fx_bool_call[] = {
  "module app;\nimport lib;\nexport fn main() -> u64 { let mut b: bool = true; if lib.take(b) { return 43; } return 0; }\n",
  "module lib;\nexport fn take(v: bool) -> bool { return v; }\n"
};
/* A FIELD READ, THEN A STORE INTO A LOCAL CELL.
 *
 * A record field is read through a memory ACCESS, and the value that comes
 * back carries that access's space. Storing it into a local cell is the
 * step where the two meet. The answer below is EXECUTED: the produced PE
 * must answer 42, and a refusal is a failure and not an answer. */
static const char *const fx_field_to_store[] = {
  "module app;\nstruct Box{value:u64}\n"
  "export fn main() -> u64 { let b: Box = Box{value:42}; let value: u64 = b.value; let mut x: u64 = 0; x = value; return x; }\n"
};
/* THE SAME FIELD, DIRECTLY INTO THE INITIALIZER OF A CELL. The other half of
 * the same shape: the value is written where the cell is made. */
static const char *const fx_field_to_cell[] = {
  "module app;\nstruct Box{value:u64}\n"
  "export fn main() -> u64 { let b: Box = Box{value:42}; let mut x: u64 = b.value; return x; }\n"
};
/* THE SAME SHAPE AT EIGHT BITS. A byte read out of a buffer lands in an
 * eight bit cell, and the cell is what the size question is about. */
static const char *const fx_byte_to_cell[] = {
  "module app;\nexport fn main() -> u64 { let b: buf<u8> = alloc(runtime(), 1); b[0] = 42; let mut x: u8 = b[0]; return u64(x); }\n"
};
/* main has ordinal 1. Its private base collides with a reachable export,
 * and suffix 1 collides with an UNREACHABLE export. The helper likewise
 * reserves a private unreachable name and an exported unreachable name.
 * Both modes must therefore choose suffix 2, as the original full AST scan
 * did, even though the closed unit omits the declarations that reserve it. */
static const char *const fx_name_collisions[] = {
  "module app;\nexport fn main() -> u64 { return native_fn_1(); }\n"
  "export fn native_fn_1() -> u64 { return 42; }\n"
  "export fn native_fn_1_1() -> u64 { return 99; }\n"
  "fn native_rt_helper() -> u64 { return 0; }\n"
  "export fn native_rt_helper_1() -> u64 { return 0; }\n"
};
static const char *const fx_direct_chain[] = {
  "module app;\nexport fn main() -> u64 { return a(); }\n"
  "fn a() -> u64 { return b(); }\nfn b() -> u64 { return 42; }\n"
};
static const char *const fx_direct_late_main[] = {
  "module app;\nfn a() -> u64 { return 42; }\n"
  "export fn main() -> u64 { return a(); }\n"
};
static const char *const fx_direct_repeat[] = {
  "module app;\nexport fn main() -> u64 { return a(2) + a(1); }\n"
  "fn a(n: u64) -> u64 { if n == 0 { return 21; } return a(n - 1); }\n"
};
static const char *const fx_direct_cycle[] = {
  "module app;\nexport fn main() -> u64 { return a(3); }\n"
  "fn a(n: u64) -> u64 { if n == 0 { return 42; } return b(n - 1); }\n"
  "fn b(n: u64) -> u64 { if n == 0 { return 42; } return a(n - 1); }\n"
};

static const struct Fixture FIXTURES[] = {
  { fx_two_modules,   2, 0, 42, 0, 0, 1 },
  { fx_private_names, 2, 0, 42, 0, 0, 1 },
  { fx_two_files,     3, 0, 42, 0, 0, 1 },
  { fx_cycle,         3, 0, 42, 0, 0, 1 },
  { fx_record_buffer, 2, 0, 42, 0, 0, 1 },
  { fx_twelve,        1, 0, 12, 0, 0, 1 },
  { fx_mutable,       1, 0,  7, 0, 0, 1 },
  { fx_missing_import,1, 0,  0, 0, 1, 1 },
  { fx_private_access,2, 0,  0, 0, 1, 1 },
  { fx_diamond,       4, 0, 42, 0, 0, 0 },
  { fx_forward,       1, 0, 42, 0, 0, 0 },
  { fx_bool_cmp_false,1, 0, 42, 0, 0, 1 },
  { fx_bool_cmp_true, 1, 0, 43, 0, 0, 1 },
  { fx_bool_loop,     1, 0, 42, 0, 0, 1 },
  { fx_bool_call,     2, 0, 43, 0, 0, 1 },
  { fx_field_to_store,1, 0, 42, 0, 0, 1 },
  { fx_field_to_cell, 1, 0, 42, 0, 0, 1 },
  { fx_byte_to_cell,  1, 0, 42, 0, 0, 1 },
  { fx_name_collisions,1,0,42, 0, 0, 1 },
  { fx_direct_chain,  1, 0, 42, 0, 0, 1 },
  { fx_direct_late_main,1,0,42,0, 0, 1 },
  { fx_direct_repeat, 1, 0, 42, 0, 0, 1 },
  { fx_direct_cycle,  1, 0, 42, 0, 0, 1 }
};
#define FIXTURE_N ((unsigned)(sizeof FIXTURES / sizeof FIXTURES[0]))
/* THE ROOT SELECTION'S ROWS. Each one must be refused with E_ROOT, the root
 * selection's own code, and none of them consults the C reference. */
static const struct Fixture ROOT_FIXTURES[] = {
  { fx_no_main,        1, 0, 0, 0, 1, 0 },
  { fx_two_mains,      2, 0, 0, 0, 1, 0 },
  { fx_main_elsewhere, 2, 0, 0, 0, 1, 0 }
};
#define ROOT_FIXTURE_N ((unsigned)(sizeof ROOT_FIXTURES / sizeof ROOT_FIXTURES[0]))
#define MANY_E_ROOT 973

/* THE BLOB: the sources copied one after another, and the span of each. The
 * frontend refuses overlapping spans and a span outside the blob, so the
 * spans here are the contract and not a convenience. */
static size_t build_blob(const struct Fixture *f,char *blob,size_t cap,uint64_t *spans) {
  size_t at=0;
  for(unsigned i=0;i<f->count;i++) {
    size_t l=strlen(f->sources[i]);
    if(at+l>cap) return 0;
    memcpy(blob+at,f->sources[i],l);
    spans[i*2]=(uint64_t)at;spans[i*2+1]=(uint64_t)l;
    at+=l;
  }
  return at;
}

/* A FAULT IN THE HARNESS IS NOT A REFUSAL OF THE SOURCES. The sentinel is a
 * value no stage produces, so a reader can tell "the pipeline refused" from
 * "the harness lost the context". */
#define MANY_FAULT UINT64_C(0xfeedfacedeadbeef)

/* THE PIPELINE CALL. The flat argument list is the frontend's own sixteen
 * words (the blob, the spans, the count, the root and the five tables) plus
 * the ABI2 outputs: twelve buffers, two words each, and five scalars, so
 * TWENTY NINE words, plus the MODE, which is the thirtieth, plus the BATCH's
 * two range numbers, which are the last two. The count is the array's own
 * size, because a count that does not match the callee's arity is refused by
 * the ABI before the callee runs -- and a count that is two words too long
 * would be refused as NV2_ARGUMENT, which is a link error and not the
 * capability being measured.
 * The caps are the CALLER'S, so the small fixtures and the audit lend the
 * pipeline different budgets and the flat words carry the same numbers the
 * buffers were borrowed with. */
static uint64_t call_many(const NovaHostImage *image,const char *blob,size_t blob_len,
                          const uint64_t *spans,uint64_t count,uint64_t root_idx,uint64_t mode,
                          uint64_t batch_start,uint64_t batch_limit,
                          const struct Caps *cp,uint64_t capacity,uint64_t *scratch,uint8_t *decls,
                          uint8_t *pe_out,uint64_t *pe_len,uint64_t *report,uint64_t *fault) {
  pe_len[0]=0;
  if(fault) { fault[0]=0;fault[1]=0;fault[2]=0; }
  NovaContextV2 c={0};
  if(!nova_context_init_v2(&c)) { fprintf(stderr,"MANY_FAULT context init failed\n"); return MANY_FAULT; }
  uint64_t *nodes=scratch;
  uint64_t *scopes=scratch+cp->nodes;
  uint64_t *binds=scopes+cp->sides;
  uint64_t *fields=binds+cp->binds;
  uint64_t *modules=fields+cp->fields;
  uint64_t *words=modules+cp->modules;
  uint64_t sh=nova_borrow_v2(&c,(void *)blob,blob_len,0);
  uint64_t sph=nova_borrow_v2(&c,(void *)spans,count*2*sizeof(uint64_t),0);
  uint64_t n1=nova_borrow_v2(&c,nodes,cp->nodes*8,1);
  uint64_t n2=nova_borrow_v2(&c,scopes,cp->sides*8,1);
  uint64_t n3=nova_borrow_v2(&c,binds,cp->binds*8,1);
  uint64_t n4=nova_borrow_v2(&c,fields,cp->fields*8,1);
  uint64_t n5=nova_borrow_v2(&c,modules,cp->modules*8,1);
  uint64_t n6=nova_borrow_v2(&c,words,cp->mir*8,1);
  uint64_t dh=nova_borrow_v2(&c,decls,cp->decls,1);
  uint64_t oh=nova_borrow_v2(&c,pe_out,cp->pe,1);
  uint64_t lh=nova_borrow_v2(&c,pe_len,MANY_LENGTHS*sizeof(uint64_t),1);
  uint64_t rh=nova_borrow_v2(&c,report,MANY_REPORT*sizeof(uint64_t),1);
  int borrowed=(sh!=0)&&(count==0||sph!=0)&&n1!=0&&n2!=0&&n3!=0&&n4!=0&&n5!=0&&n6!=0&&dh!=0&&oh!=0&&lh!=0&&rh!=0;
  CHECK(borrowed,"the many pipeline borrows completed");
  if(!borrowed||c.error!=0) {
    fprintf(stderr,"MANY_FAULT borrow error=%llu\n",(unsigned long long)c.error);
    uint64_t e0=c.error,e1=c.error_source,e2=c.error_offset;
    if(fault) { fault[0]=e0;fault[1]=e1;fault[2]=e2; }
    nova_context_destroy_v2(&c);
    return MANY_FAULT;
  }
  uint64_t args[]={sh,(uint64_t)blob_len,sph,count*2,count,root_idx,
    n1,cp->nodes,n2,cp->sides,n3,cp->binds,n4,cp->fields,n5,cp->modules,
    n6,cp->mir,capacity?capacity:cp->mir,dh,cp->decls,cp->decls,oh,cp->pe,cp->pe,lh,MANY_LENGTHS,rh,MANY_REPORT,
    mode,batch_start,batch_limit};
  uint64_t argc=(uint64_t)(sizeof(args)/sizeof(args[0]));
  CHECK(argc==32,"the many entry takes thirty two flat words");
  uint64_t returned=image->entry(&c,args,argc);
  /* THE FAULT IS CAPTURED BEFORE THE CONTEXT IS DESTROYED, and it is never
   * attributed to the frontend: a context that faulted did not refuse
   * anything, and a refusal case must not pass on a fault. */
  uint64_t runtime=c.error,source=c.error_source,offset=c.error_offset;
  if(runtime!=0) fprintf(stderr,"MANY_FAULT runtime error=%llu source=%llu offset=%llu\n",
                         (unsigned long long)runtime,(unsigned long long)source,(unsigned long long)offset);
  if(fault) { fault[0]=runtime;fault[1]=source;fault[2]=offset; }
  nova_context_destroy_v2(&c);
  if(runtime!=0) return MANY_FAULT;
  return returned;
}

/* THE PE IS EXECUTED FOR REAL, in a bounded child, on the real ABI2 runtime.
 * The parent's context is copied, so every refusal has an independent initial
 * error state. */
static void invoke_pe(CallbackImage *pe,NovaContextV2 *ctx,uint64_t want,uint64_t error) {
  cases++;int fd[2];if(pipe(fd)){CHECK(0,"MANY PE pipe");return;}
  pid_t pid=fork();
  if(pid==0) {
    alarm(5);close(fd[0]);uint64_t result=((Abi2Entry)pe->entry)(ctx,NULL,0);
    uint64_t packet[4]={result,ctx?ctx->error:0,ctx?ctx->error_source:0,ctx?ctx->error_offset:0};
    int ok=write(fd[1],packet,sizeof packet)==(ssize_t)sizeof packet;_exit(ok?0:3);
  }
  close(fd[1]);if(pid<0){close(fd[0]);CHECK(0,"MANY PE fork");return;}
  uint64_t packet[4]={0};ssize_t got=read(fd[0],packet,sizeof packet);close(fd[0]);int status=0;waitpid(pid,&status,0);
  int ok=WIFEXITED(status)&&WEXITSTATUS(status)==0&&got==(ssize_t)sizeof packet&&packet[0]==want&&packet[1]==error;
  if(!ok)fprintf(stderr,"MANY_PE result=%llu error=%llu want=%llu/%llu status=%d bytes=%zd\n",(unsigned long long)packet[0],(unsigned long long)packet[1],(unsigned long long)want,(unsigned long long)error,status,got);
  CHECK(ok,"the produced PE answers the oracle on the real ABI2 runtime");
  if(ok)abi_native++;
}

/* THE FUNCTIONS THE EMITTED UNIT CARRIES, COUNTED FROM THE DECLARATION TEXT.
 *
 * THE TEXT IS SCANNED AND NOT MATCHED. A declaration of the unit is the
 * KEYWORD `fn` -- a word of its own, followed by a space or by the
 * parameter list's parenthesis. A function's own name may hold the letters
 * "fn" ("native_fn_3"), a comment may mention the keyword, and a string
 * literal may hold it: none of those is a declaration.
 *
 * THE COUNT IS THE DECLARATIONS OF THE UNIT, and it counts the IMPORTS as
 * well as the definitions, because an import is a declaration of the unit
 * too: the objects are joined on those names.
 *
 * THE SCAN IS BOUNDED BY THE TEXT ITSELF, and it reads no counter the
 * producer published: it is a SECOND measurement of the same text and not a
 * copy of the first one. */
static int count_ident_byte(uint8_t c) {
  return (c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_';
}
static uint64_t count_functions(const uint8_t *decls,uint64_t n) {
  uint64_t count=0,at=0;
  while(at<n) {
    uint8_t ch=decls[at];
    /* A LINE COMMENT RUNS TO THE END OF ITS LINE, and the keyword inside it
     * is text and not a declaration. */
    if(ch=='/' && at+1<n && decls[at+1]=='/') {
      while(at<n && decls[at]!='\n') at++;
      continue;
    }
    /* A STRING LITERAL IS SKIPPED WHOLE, and the keyword inside it is text. */
    if(ch=='"') {
      at++;
      while(at<n) {
        if(decls[at]=='\\') { at+=2; continue; }
        if(decls[at]=='"') { at++; break; }
        at++;
      }
      continue;
    }
    /* THE KEYWORD, AS A WORD OF ITS OWN. */
    if(ch=='f' && at+1<n && decls[at+1]=='n') {
      int before_ok=(at==0)||!count_ident_byte(decls[at-1]);
      uint64_t after=at+2;
      int after_ok=(after>=n)||(decls[after]==' '||decls[after]=='\t'||decls[after]=='(');
      if(before_ok && after_ok) count++;
    }
    at++;
  }
  return count;
}

/* THE COUNTER'S OWN CONTROLS.
 *
 * A text with one import removed counts one declaration less, and a text
 * with the keyword inside a comment counts the same. The texts are BUILT
 * HERE and are not the producer's: the counter is measured against texts it
 * did not read a counter from, and a counter that always answered the
 * producer's number would pass every row and prove nothing. */
static void count_function_controls(void) {
  cases++;
  const char *with_import="module nova.native\n"
    "import nova.native.native_fn_2 as native_fn_2: fn(in p0:u64)->u64\n"
    "export fn native_fn_1(in p0:u64)->u64 effects {} clobbers {rax} { return 0;}\n";
  const char *without_import="module nova.native\n"
    "export fn native_fn_1(in p0:u64)->u64 effects {} clobbers {rax} { return 0;}\n";
  const char *with_comment="module nova.native\n"
    "// fn native_fn_9 is a comment and not a declaration\n"
    "import nova.native.native_fn_2 as native_fn_2: fn(in p0:u64)->u64\n"
    "export fn native_fn_1(in p0:u64)->u64 effects {} clobbers {rax} { return 0;}\n";
  uint64_t a=count_functions((const uint8_t *)with_import,strlen(with_import));
  uint64_t b=count_functions((const uint8_t *)without_import,strlen(without_import));
  uint64_t c=count_functions((const uint8_t *)with_comment,strlen(with_comment));
  CHECK(a==2,"the counter counts the import and the definition");
  CHECK(b==1,"the counter loses exactly the import that was removed");
  CHECK(c==2,"the counter does not count the keyword inside a comment");
}

/* WHAT ONE RUN PRODUCED. The numbers are the ones the run produced, and they
 * are what the closed mode is MEASURED with: the MIR image's bytes, the
 * declaration text's bytes, the functions the unit carries, and the bytes
 * the run delivered (a PE, or an object for a batch). */
struct Measured { uint64_t mir_bytes, decl_bytes, functions, out_bytes; };

static int declaration_has(const uint8_t *decls,uint64_t length,const char *text) {
  size_t n=strlen(text);
  if(n>length) return 0;
  for(uint64_t i=0;i<=length-n;i++)
    if(memcmp(decls+i,text,n)==0) return 1;
  return 0;
}

/* ONE FIXTURE, END TO END. */
static void run_fixture(const NovaHostImage *image,NovaContextV2 *ctx,const struct Fixture *f,uint64_t exact_code,
                        uint64_t mode,uint64_t batch_start,uint64_t batch_limit,
                        char *blob,uint64_t *spans,uint64_t *scratch,uint8_t *decls,uint8_t *pe_out,
                        uint64_t *pe_len,uint64_t *report,struct Measured *m) {
  cases++;
  size_t blob_len=build_blob(f,blob,MANY_BLOB,spans);
  CHECK(blob_len>0,"the fixture's sources fit the blob");
  if(blob_len==0) return;
  /* THE C REFERENCE'S OWN VERDICT, where it has one. It is a DIFFERENT
   * parser from the Nova one under test, so its agreement is information and
   * not a tautology. The verdict must be EXACTLY the opposite of the
   * expectation: a negative case the C reference ACCEPTS is a disagreement,
   * and a positive case it REFUSES is a disagreement. The out of range root
   * has no oracle, because the C reference has no root parameter. */
  if(f->oracle) {
    CHECK(f->count<=16,"the fixture's source count fits the oracle table");
    NtFInput refs[16];
    for(unsigned i=0;i<f->count && i<16;i++) refs[i]=(NtFInput){"many.nova",f->sources[i],strlen(f->sources[i])};
    NtDiagnostic diag;
    memset(&diag,0,sizeof diag);
    int accepted=nova_check_many_v2(refs,f->count,&diag);
    int expect_accept=(f->refused==0);
    if((accepted!=0)!=expect_accept)
      fprintf(stderr,"MANY_ORACLE accepted=%d code=%u line=%u column=%u\n",accepted,
              (unsigned)diag.code,(unsigned)diag.line,(unsigned)diag.column);
    CHECK((accepted!=0)==expect_accept,"the C reference agrees on the sources");
  }
  for(unsigned i=0;i<MANY_REPORT;i++) report[i]=0;
  uint64_t code=call_many(image,blob,blob_len,spans,f->count,f->root,mode,batch_start,batch_limit,&SMALL_CAPS,0,scratch,decls,pe_out,pe_len,report,NULL);
  /* THE STAGE SAYS WHICH LAYOUT THE REPORT HOLDS. The frontend writes
   * [code, reason, line, column] and the lower writes [node, line, code,
   * column]; printing one with the other's names would show a code where a
   * line belongs. */
  if(code!=0) {
    if(code==MANY_FAULT) fprintf(stderr,"MANY_FAULT the harness lost the context; no verdict\n");
    else if(report[8]==1)
      fprintf(stderr,"MANY_FRONTEND code=%llu reason=%llu line=%llu column=%llu\n",
              (unsigned long long)report[0],(unsigned long long)report[1],
              (unsigned long long)report[2],(unsigned long long)report[3]);
    else if(report[8]==2)
      fprintf(stderr,"MANY_LOWER code=%llu line=%llu column=%llu node=%llu\n",
              (unsigned long long)report[2],(unsigned long long)report[1],
              (unsigned long long)report[3],(unsigned long long)report[0]);
    else if(report[8]==5 || report[8]==6)
      /* THE PIPELINE'S OWN STAGES, AND THE STAGE SAYS WHICH ONE. The code of
       * a pipeline refusal is the ninth word and the stage the eighth, and
       * the first four words are that stage's own layout, which is not this
       * gate's business: they are printed as they are. */
      fprintf(stderr,"MANY_STAGE stage=%llu code=%llu report=%llu/%llu/%llu/%llu\n",
              (unsigned long long)report[8],(unsigned long long)report[9],
              (unsigned long long)report[0],(unsigned long long)report[1],
              (unsigned long long)report[2],(unsigned long long)report[3]);
    else
      fprintf(stderr,"MANY_OBJECT code=%llu report=%llu/%llu/%llu/%llu\n",
              (unsigned long long)report[2],(unsigned long long)report[0],
              (unsigned long long)report[1],(unsigned long long)report[3],
              (unsigned long long)report[4]);
  }
  if(f->refused) {
    /* A FAULT IS NOT A REFUSAL: a context that faulted refused nothing. */
    CHECK(code!=0&&code!=MANY_FAULT,"the pipeline refuses the sources");
    if(exact_code!=0) CHECK(code==exact_code,"the refusal carries the expected code");
    CHECK(pe_len[0]==0,"the refusal produced no PE");
    if(m) { m->mir_bytes=0;m->decl_bytes=0;m->functions=0;m->out_bytes=0; }
    return;
  }
  CHECK(code==0,"the many sources lower to a native ABI2 PE");
  if(code!=0) return;
  CHECK(pe_len[0]>0,"the produced PE has a length");
  if(f->sources==fx_name_collisions) {
    CHECK(declaration_has(decls,pe_len[1],"fn native_fn_1_2("),
          "main ordinal 1 keeps exact suffix 2 despite the unreachable exported collision");
    CHECK(declaration_has(decls,pe_len[1],"fn native_rt_helper_2("),
          "the helper reserves every function name, including unreachable private functions");
    CHECK(declaration_has(decls,pe_len[1],"fn native_fn_2("),
          "the reachable export keeps its ABI2 private name for ordinal 2");
    CHECK(declaration_has(decls,pe_len[1],"fn native_fn_3(")==(mode==0),
          "the export reserving suffix 1 is emitted only in the normal mode");
    if(mode==1) {
      CHECK(pe_len[7]==5,"the collision fixture declares five source functions");
      CHECK(pe_len[8]==2,"only main and its called export are reachable");
    }
  }
  /* WHAT THIS RUN PRODUCED, MEASURED AND NOT ASSERTED: the numbers are the
   * ones this run produced, and the rows that compare them read them here. */
  if(m) {
    m->mir_bytes=pe_len[2];m->decl_bytes=pe_len[1];m->out_bytes=pe_len[0];
    m->functions=count_functions(decls,pe_len[1]);
  }
  /* A BATCH IS AN OBJECT AND NOT A PROGRAM: it has no entry of its own
   * unless it is the first batch, so it is measured and not executed. */
  if(mode==2) return;
  char why[256]={0};CallbackImage pe={0};
  int rc=map_callback_pe(pe_out,(size_t)pe_len[0],&pe,why,sizeof why);
  if(rc)fprintf(stderr,"MANY_MAP %s\n",why);
  CHECK(rc==0,"the produced PE maps");
  if(rc) return;
  invoke_pe(&pe,ctx,f->want,f->error);
  munmap(pe.base,pe.size);
}

/* A PROGRAM WITH A BIG UNCALLED FUNCTION.
 *
 * The text is BUILT and not written by hand: two hundred statements that
 * nobody calls. The function is private, so the closed mode drops it with
 * the private naming path, and the image it would have taken is the image
 * the closed mode must not carry. */
static char big_dead_source[32768];
static void build_big_dead_source(void) {
  char *p=big_dead_source;
  size_t room=sizeof big_dead_source;
  int n=snprintf(p,room,"module app;\nexport fn main() -> u64 { return 42; }\nfn dead_one() -> u64 {\n  let mut t: u64 = 0;\n");
  if(n<0||(size_t)n>=room) { big_dead_source[0]=0;return; }
  p+=n;room-=(size_t)n;
  for(int i=0;i<200 && room>64;i++) {
    n=snprintf(p,room,"  t = t + %d;\n",i+1);
    if(n<0||(size_t)n>=room) break;
    p+=n;room-=(size_t)n;
  }
  n=snprintf(p,room,"  return t;\n}\n");
  (void)n;
}

/* THE CLOSED MODE'S ROWS.
 *
 * THE SAME PROGRAM IN BOTH MODES: the closed mode answers what the normal
 * mode answers, and the root selection's own refusals are the same
 * refusals. THE MEASUREMENT: a program with a big uncalled function must
 * produce a SMALLER image in the closed mode, and the numbers that say so
 * are the numbers this run produced. */
static void run_closed_rows(const NovaHostImage *image,NovaContextV2 *ctx,char *blob,uint64_t *spans,
                             uint64_t *scratch,uint8_t *decls,uint8_t *pe_out,uint64_t *pe_len,uint64_t *report) {
  /* EVERY FIXTURE, IN BOTH MODES. The answers are the fixture's own, so the
   * two runs must agree with each other and with the fixture. */
  for(unsigned i=0;i<FIXTURE_N;i++) {
    struct Measured normal={0,0,0,0},closed={0,0,0,0};
    run_fixture(image,ctx,&FIXTURES[i],0,0,0,0,blob,spans,scratch,decls,pe_out,pe_len,report,&normal);
    run_fixture(image,ctx,&FIXTURES[i],0,1,0,0,blob,spans,scratch,decls,pe_out,pe_len,report,&closed);
    if(FIXTURES[i].refused) {
      CHECK(normal.out_bytes==0&&closed.out_bytes==0,"the refused program produced no PE in either mode");
      continue;
    }
    CHECK(closed.functions>0,"the closed mode carries the program's functions");
    CHECK(normal.functions>=closed.functions,"the closed mode carries no more functions than the normal mode");
    /* THE PUBLISHED COUNT AND THE COUNTED TEXT ARE TWO MEASUREMENTS OF THE
     * SAME THING, and they must agree: the lower's own count of the emitted
     * declarations and the declaration text the harness read.
     *
     * THE THREE COUNTS ARE THREE DIFFERENT THINGS: the functions the program
     * declares, the ones the root module's main can reach, and the
     * declarations the emitted unit carries. The last one is the reachable
     * ones AND the three synthetic ones the lower writes for every program,
     * so it is the only one that may be larger than the reachable count. */
    CHECK(pe_len[9]==closed.functions,"the closed mode's published count agrees with the emitted text");
    CHECK(pe_len[7]>=pe_len[8],"the reachable functions are declared functions");
    CHECK(pe_len[9]==pe_len[8]+3,"the emitted unit carries the reachable functions and the three synthetic ones");
    CHECK(pe_len[8]<=closed.functions,"the reachable functions are in the emitted unit");
  }
  /* THE ROOT SELECTION'S ROWS, IN THE CLOSED MODE. The refusal is the root
   * selection's own code, and the closed mode does not change it. */
  for(unsigned i=0;i<ROOT_FIXTURE_N;i++)
    run_fixture(image,ctx,&ROOT_FIXTURES[i],MANY_E_ROOT,1,0,0,blob,spans,scratch,decls,pe_out,pe_len,report,NULL);
  /* THE BIG UNCALLED FUNCTION. The image the closed mode produces is
   * SMALLER, and the answer is the same. */
  {
    build_big_dead_source();
    const char *const sources[]={big_dead_source};
    struct Fixture f={sources,1,0,42,0,0,0};
    struct Measured normal={0,0,0,0},closed={0,0,0,0};
    run_fixture(image,ctx,&f,0,0,0,0,blob,spans,scratch,decls,pe_out,pe_len,report,&normal);
    run_fixture(image,ctx,&f,0,1,0,0,blob,spans,scratch,decls,pe_out,pe_len,report,&closed);
    fprintf(stderr,"MANY_CLOSED normal_mir=%llu closed_mir=%llu normal_decls=%llu closed_decls=%llu normal_functions=%llu closed_functions=%llu declared=%llu reachable=%llu emitted=%llu\n",
            (unsigned long long)normal.mir_bytes,(unsigned long long)closed.mir_bytes,
            (unsigned long long)normal.decl_bytes,(unsigned long long)closed.decl_bytes,
            (unsigned long long)normal.functions,(unsigned long long)closed.functions,
            (unsigned long long)pe_len[7],(unsigned long long)pe_len[8],(unsigned long long)pe_len[9]);
    CHECK(closed.mir_bytes<normal.mir_bytes,"the closed mode's image is smaller than the normal mode's");
    CHECK(closed.functions<normal.functions,"the closed mode carries fewer functions");
    CHECK(closed.decl_bytes<normal.decl_bytes,"the closed mode's declaration text is shorter");
    /* THE DEAD FUNCTION IS THE WHOLE DIFFERENCE: the program declares two
     * functions, the main reaches one of them, and the unit that comes out
     * carries the reachable one and the three synthetic ones. */
    CHECK(pe_len[7]==2,"the program declares two functions");
    CHECK(pe_len[8]==1,"the closed mode reaches the main and nothing else");
    CHECK(pe_len[9]==4,"the emitted unit carries the reachable function and the three synthetic ones");
  }
  /* THE SAME PROGRAM, TWICE, IN THE CLOSED MODE: THE SAME PE. A mode whose
   * output moved between two runs of the same input could not be measured. */
  {
    uint8_t *first=(uint8_t *)malloc(MANY_PE);
    CHECK(first!=NULL,"the determinism buffer is allocated");
    if(first) {
      struct Measured one={0,0,0,0},two={0,0,0,0};
      run_fixture(image,ctx,&FIXTURES[0],0,1,0,0,blob,spans,scratch,decls,pe_out,pe_len,report,&one);
      uint64_t first_len=pe_len[0];
      if(first_len>0&&first_len<=MANY_PE) memcpy(first,pe_out,first_len);
      run_fixture(image,ctx,&FIXTURES[0],0,1,0,0,blob,spans,scratch,decls,pe_out,pe_len,report,&two);
      CHECK(pe_len[0]==first_len,"the closed mode's PE has the same length twice");
      if(pe_len[0]==first_len&&first_len>0)
        CHECK(memcmp(first,pe_out,first_len)==0,"the closed mode's PE is byte for byte the same twice");
      CHECK(one.mir_bytes==two.mir_bytes,"the closed mode's image has the same size twice");
      free(first);
    }
  }
}

/* FOUR REACHABLE FUNCTIONS, FOR THE BATCH. The main calls the three others,
 * so all four are reachable and the ranks are four of them. */
static const char *const fx_batch[] = {
  "module app;\nexport fn main() -> u64 { return a() + b() + c(); }\n"
  "fn a() -> u64 { return 1; }\nfn b() -> u64 { return 2; }\nfn c() -> u64 { return 39; }\n"
};
/* Inspect the emitted source imports themselves, independently of the
 * lower's report. Synthetic imports use different names. */
static uint64_t count_source_imports(const uint8_t *decls,uint64_t length) {
  const char *prefix="import nova.native.native_fn_";
  size_t n=strlen(prefix);uint64_t count=0;
  if(n>length) return 0;
  for(uint64_t i=0;i<=length-n;i++)
    if(memcmp(decls+i,prefix,n)==0) count++;
  return count;
}
static void run_direct_import_rows(const NovaHostImage *image,NovaContextV2 *ctx,char *blob,uint64_t *spans,
                                  uint64_t *scratch,uint8_t *decls,uint8_t *pe_out,uint64_t *pe_len,uint64_t *report) {
  struct DirectRow {
    const char *const *sources;
    unsigned reachable,start,limit,selected,mask,imports;
  };
  static const struct DirectRow rows[]={
    {fx_direct_chain,3,0,1,1,1u<<2,1}, /* a, but not its callee b */
    {fx_direct_chain,3,1,1,1,1u<<3,1},
    {fx_direct_chain,3,2,1,1,0,0},
    {fx_direct_chain,3,1,2,2,0,0},     /* a and b both defined here */
    {fx_direct_late_main,2,0,1,1,1u<<2,1}, /* wrapper imports main */
    {fx_direct_late_main,2,1,1,1,1u<<1,1},
    {fx_direct_repeat,2,0,1,1,1u<<2,1}, /* two calls, one import */
    {fx_direct_repeat,2,1,1,1,0,0},     /* self recursion is local */
    {fx_direct_cycle,3,0,1,1,1u<<2,1},
    {fx_direct_cycle,3,1,1,1,1u<<3,1},
    {fx_direct_cycle,3,2,1,1,1u<<2,1},
    {fx_direct_cycle,3,1,2,2,0,0}      /* mutual recursion is local */
  };
  for(unsigned i=0;i<sizeof rows/sizeof rows[0];i++) {
    const struct DirectRow *r=&rows[i];
    struct Fixture f={r->sources,1,0,42,0,0,0};
    struct Measured m={0,0,0,0};
    run_fixture(image,ctx,&f,0,2,r->start,r->limit,blob,spans,scratch,decls,pe_out,pe_len,report,&m);
    CHECK(m.out_bytes>0,"the direct-import batch produces a real object");
    if(m.out_bytes==0) continue;
    CHECK(count_source_imports(decls,pe_len[1])==r->imports,"the emitted source import count is exact");
    for(unsigned ord=1;ord<=r->reachable;ord++) {
      char text[128];
      snprintf(text,sizeof text,"import nova.native.native_fn_%u as native_fn_%u:",ord,ord);
      CHECK(declaration_has(decls,pe_len[1],text)==((r->mask&(1u<<ord))!=0),
            "the batch imports exactly the expected direct target ordinals");
    }
    uint64_t expected=r->selected+r->imports+(r->start==0?3:2);
    CHECK(m.functions==expected,"the counted text carries definitions, direct imports and synthetic declarations");
    CHECK(pe_len[9]==expected,"the emitted count agrees with the exact batch contents");
    CHECK(pe_len[8]==r->reachable,"direct imports preserve global reachability");
    CHECK(pe_len[10]==r->selected,"direct imports preserve the selected ranks");
  }
}
/* THE BATCH'S ROWS.
 *
 * ONE PROGRAM, TWO REAL OBJECTS. The program is the four functions fixture:
 * the main calls the three others, so all four are reachable and the ranks
 * count them. The first batch owns the first rank and the second owns the
 * second, and each object carries the functions it defines and the imports
 * of their direct callees outside that object.
 *
 * THE RANGE IS REFUSED WHEN IT NAMES NOTHING: a limit of zero and a start
 * past the last reachable function are refusals and not an empty object. */
static void run_batch_rows(const NovaHostImage *image,NovaContextV2 *ctx,char *blob,uint64_t *spans,
                            uint64_t *scratch,uint8_t *decls,uint8_t *pe_out,uint64_t *pe_len,uint64_t *report) {
  struct Fixture f={fx_batch,1,0,42,0,0,0};
  struct Measured first={0,0,0,0},second={0,0,0,0};
  run_fixture(image,ctx,&f,0,2,0,1,blob,spans,scratch,decls,pe_out,pe_len,report,&first);
  /* THE FIRST BATCH OWNS THE FIRST REACHABLE FUNCTION AND THE ENTRY. */
  CHECK(first.out_bytes>0,"the first batch produced an object");
  CHECK(pe_len[8]==4,"the program has four reachable functions");
  CHECK(pe_len[10]==1,"the first batch defines one function");
  /* THE COUNTS ARE REAL. The first batch carries the four reachable
   * functions and the three synthetic ones. */
  CHECK(pe_len[9]==7,"the first batch carries the reachable functions and the three synthetic ones");
  CHECK(first.functions==7,"the first batch's text carries seven declarations");
  run_fixture(image,ctx,&f,0,2,1,1,blob,spans,scratch,decls,pe_out,pe_len,report,&second);
  CHECK(second.out_bytes>0,"the second batch produced an object");
  CHECK(pe_len[10]==1,"the second batch defines one function");
  CHECK(second.mir_bytes<first.mir_bytes,"the second batch's image is smaller than the first batch's");
  /* a() has no direct callee: this batch carries its one definition and
   * the two synthetic imports, with no unrelated source declaration. */
  CHECK(pe_len[9]==3,"the second batch carries one definition and the two synthetic imports");
  CHECK(second.functions==3,"the second batch's text carries three declarations");
  /* A LIMIT OF UINT64_MAX SELECTS EVERY FUNCTION THAT IS LEFT, and it does
   * not wrap around to an empty range. */
  {
    struct Measured all={0,0,0,0};
    run_fixture(image,ctx,&f,0,2,1,UINT64_MAX,blob,spans,scratch,decls,pe_out,pe_len,report,&all);
    CHECK(all.out_bytes>0,"a limit of UINT64_MAX produced an object");
    CHECK(pe_len[10]==3,"a limit of UINT64_MAX selected every function that was left");
  }
  /* THE RANGE IS REFUSED WHEN IT NAMES NOTHING. */
  {
    cases++;
    size_t blob_len=build_blob(&f,blob,MANY_BLOB,spans);
    CHECK(blob_len>0,"the batch fixture fits the blob");
    if(blob_len>0) {
      for(unsigned i=0;i<MANY_REPORT;i++) report[i]=0;
      uint64_t code=call_many(image,blob,blob_len,spans,f.count,f.root,2,0,0,&SMALL_CAPS,0,scratch,decls,pe_out,pe_len,report,NULL);
      CHECK(code!=0&&code!=MANY_FAULT,"a limit of zero is a refusal and not an empty object");
      CHECK(pe_len[0]==0,"the refused range produced no object");
      for(unsigned i=0;i<MANY_REPORT;i++) report[i]=0;
      code=call_many(image,blob,blob_len,spans,f.count,f.root,2,99,1,&SMALL_CAPS,0,scratch,decls,pe_out,pe_len,report,NULL);
      CHECK(code!=0&&code!=MANY_FAULT,"a start past the last function is a refusal");
      CHECK(pe_len[0]==0,"the refused range produced no object");
    }
  }
  run_direct_import_rows(image,ctx,blob,spans,scratch,decls,pe_out,pe_len,report);
}
/* ---- the audit: the compiler's own sources, as ONE program ---------------- *//*
 * THE AUDIT IS OPTIONAL AND OFF BY DEFAULT. It runs only when
 * NOVA_NATIVE_SOURCE_LIST names a file of paths, and it writes its artefacts
 * only into NOVA_NATIVE_AUDIT_OUT. The small fixtures' run does not touch it.
 *
 * EVERY SOURCE IS READ FROM THE SNAPSHOT AS IT IS. The list is a file of
 * paths, one per line; each path is read whole, byte for byte, and the blob
 * is those sources side by side with their real spans. No source is rewritten,
 * renamed, normalised, or concatenated into another: the C compiles ONLY the
 * producer, and the TARGETS are never compiled by C.
 */
static int audit_read_list(const char *list_path,char paths[][512],unsigned max) {
  FILE *f=fopen(list_path,"rb");
  if(!f) { fprintf(stderr,"AUDIT_LIST cannot open %s\n",list_path); return -1; }
  char line[1024];unsigned n=0;int bad=0;
  while(!bad) {
    if(!fgets(line,sizeof line,f)) break;
    size_t l=strlen(line);
    if(l>0 && line[l-1]=='\n') line[--l]=0;
    else if(l+1==sizeof line) { fprintf(stderr,"AUDIT_LIST a path is too long\n"); bad=1; break; }
    while(l>0 && line[l-1]=='\r') line[--l]=0;
    if(l==0) continue;
    /* A PATH LONGER THAN THE SLOT IS REFUSED AND NOT COPIED, and a list
     * LONGER THAN THE FRONTEND'S OWN LIMIT OF SIXTY FOUR SOURCES IS REFUSED
     * AND NOT TRUNCATED: a source the harness silently dropped would be a
     * program the audit did not measure. */
    if(l>=512) { fprintf(stderr,"AUDIT_LIST a path does not fit five hundred twelve bytes\n"); bad=1; break; }
    if(n>=max) { fprintf(stderr,"AUDIT_LIST more than %u sources\n",max); bad=1; break; }
    memcpy(paths[n],line,l+1);n++;
  }
  /* A SILENT PREFIX IS NOT A LIST. The error indicator and the close are both
   * checked, because a read that failed half way leaves the paths that were
   * read looking like a complete list, and a program measured from a truncated
   * list is not the program the list names. */
  int ioerr=ferror(f);
  int closed=fclose(f);
  if(ioerr) { fprintf(stderr,"AUDIT_LIST the read failed\n"); return -1; }
  if(closed!=0) { fprintf(stderr,"AUDIT_LIST the close failed\n"); return -1; }
  if(bad) return -1;
  if(n==0) { fprintf(stderr,"AUDIT_LIST %s is empty\n",list_path); return -1; }
  return (int)n;
}
static int audit_write(const char *dir,const char *name,const void *data,size_t n) {
  char path[1200];
  int k=snprintf(path,sizeof path,"%s/%s",dir,name);
  if(k<0||(size_t)k>=sizeof path) { fprintf(stderr,"AUDIT_OUT the path is too long\n"); return 0; }
  /* THE FILE IS CREATED EXCLUSIVELY ("wbx" is O_EXCL). A proof that
   * overwrote an older one would be indistinguishable from a proof that
   * measured nothing, so an existing file is a refusal and not a place to
   * write. */
  FILE *f=fopen(path,"wbx");
  if(!f) { fprintf(stderr,"AUDIT_OUT cannot create %s exclusively\n",path); return 0; }
  int ok=(n==0)||(fwrite(data,1,n,f)==n);
  if(fclose(f)!=0) ok=0;
  if(!ok) fprintf(stderr,"AUDIT_OUT cannot write %s\n",path);
  return ok;
}
static int audit_write_status(const char *dir,const char *status) {
  char path[1200];
  int k=snprintf(path,sizeof path,"%s/audit.status",dir);
  if(k<0||(size_t)k>=sizeof path) return 0;
  FILE *f=fopen(path,"wbx");
  if(!f) { fprintf(stderr,"AUDIT_OUT cannot create %s exclusively\n",path); return 0; }
  size_t n=strlen(status);
  int ok=(fwrite(status,1,n,f)==n);
  if(fclose(f)!=0) ok=0;
  if(!ok) fprintf(stderr,"AUDIT_OUT cannot write %s\n",path);
  return ok;
}
static int audit_write_report(const char *dir,const uint64_t *report,unsigned n) {
  char path[1200];
  int k=snprintf(path,sizeof path,"%s/audit.report",dir);
  if(k<0||(size_t)k>=sizeof path) return 0;
  FILE *f=fopen(path,"wbx");
  if(!f) { fprintf(stderr,"AUDIT_OUT cannot create %s exclusively\n",path); return 0; }
  for(unsigned i=0;i<n;i++) fprintf(f,"%u %llu\n",i,(unsigned long long)report[i]);
  int ok=(fclose(f)==0);
  if(!ok) fprintf(stderr,"AUDIT_OUT cannot write %s\n",path);
  return ok;
}
static void run_audit(const NovaHostImage *image,const char *list_path,const char *out_dir,uint64_t closed) {
  cases++;
  char paths[AUDIT_SOURCES][512];
  int n=audit_read_list(list_path,paths,AUDIT_SOURCES);
  CHECK(n>0,"the audit source list is read");
  if(n<=0) return;
  /* THE DIRECTORY MUST BE NEW, AND IT IS CREATED BEFORE THE RUN. A proof that
   * landed beside an older one would be indistinguishable from a proof that
   * measured nothing, so an existing directory is a REFUSAL and not a place to
   * write, and the run does not start. */
  if(mkdir(out_dir,0777)!=0) {
    fprintf(stderr,"AUDIT_OUT the directory %s is not new\n",out_dir);
    CHECK(0,"the audit output directory is new");
    return;
  }
  char *blob=(char *)malloc(AUDIT_BLOB);
  uint8_t *pe_out=(uint8_t *)malloc(AUDIT_PE);
  uint8_t *decls=(uint8_t *)malloc(AUDIT_DECLS);
  uint64_t *scratch=(uint64_t *)malloc((size_t)(AUDIT_NODES+AUDIT_SIDES+AUDIT_BINDS+AUDIT_FIELDS+AUDIT_MODULES+AUDIT_MIR)*sizeof(uint64_t));
  uint64_t spans[AUDIT_SOURCES*2],pe_len[MANY_LENGTHS],report[MANY_REPORT],fault[3];
  int ok=blob&&pe_out&&decls&&scratch;
  CHECK(ok,"the audit buffers are allocated");
  if(!ok) { audit_write_status(out_dir,"FAIL\n");free(scratch);free(decls);free(pe_out);free(blob);return; }
  size_t at=0,source_bytes=0;unsigned loaded=0;int broken=0;
  for(int i=0;i<n;i++) {
    size_t sz=0;char *t=loadf(paths[i],&sz);
    if(!t) { fprintf(stderr,"AUDIT_SRC cannot read %s\n",paths[i]); broken=1; break; }
    if(at+sz>AUDIT_BLOB) { fprintf(stderr,"AUDIT_BLOB %s does not fit\n",paths[i]); free(t); broken=1; break; }
    memcpy(blob+at,t,sz);spans[i*2]=(uint64_t)at;spans[i*2+1]=(uint64_t)sz;
    at+=sz;source_bytes+=sz;loaded++;free(t);
  }
  CHECK(broken==0,"the audit sources are read and fit the blob");
  if(broken) { audit_write_status(out_dir,"FAIL\n");free(scratch);free(decls);free(pe_out);free(blob);return; }
  for(unsigned i=0;i<MANY_REPORT;i++) report[i]=0;
  /* THE ROOT IS THE FIRST SOURCE OF THE LIST, which is the driver. */
  uint64_t code=call_many(image,blob,at,spans,loaded,0,closed,0,0,&AUDIT_CAPS,0,scratch,decls,pe_out,pe_len,report,fault);
  uint64_t *words=scratch+AUDIT_NODES+AUDIT_SIDES+AUDIT_BINDS+AUDIT_FIELDS+AUDIT_MODULES;
  if(code!=0) {
    /* THE REFUSAL IS KEPT WHOLE: the code, the runtime error, the source, the
     * offset and the stage. A red row with no numbers measures nothing, and a
     * bound that stops the closure is MEASURED and not widened. */
    fprintf(stderr,"AUDIT_FAIL code=%llu runtime=%llu source=%llu offset=%llu stage=%llu sources=%u source_bytes=%zu blob=%zu\n",
            (unsigned long long)code,(unsigned long long)fault[0],(unsigned long long)fault[1],
            (unsigned long long)fault[2],(unsigned long long)report[8],loaded,source_bytes,at);
    CHECK(0,"the audit lowers the compiler's own sources into a native PE");
    /* THE REFUSAL IS KEPT: the raw report, whose words the stage says how to
     * read, and an explicit status. NO PE AND NO MIR ARE WRITTEN, because a
     * partial artefact is a false proof. */
    audit_write_report(out_dir,report,MANY_REPORT);
    audit_write_status(out_dir,"FAIL\n");
  } else {
    /* THE THREE SIZES ARE CHECKED BEFORE ANYTHING IS CALLED A SUCCESS. A
     * length of zero, or one past the capacity the harness lent, is not a
     * small success: it is a refusal wearing a success's clothes, and it must
     * not become an empty file that counts as a proof. */
    uint64_t mir_bytes=pe_len[2],decl_bytes=pe_len[1],pe_bytes=pe_len[0];
    int sized=(pe_bytes>0)&&(pe_bytes<=(uint64_t)AUDIT_PE)&&
              (decl_bytes>0)&&(decl_bytes<=(uint64_t)AUDIT_DECLS)&&
              (mir_bytes>0)&&(mir_bytes<=(uint64_t)AUDIT_MIR*8);
    if(sized==0) {
      fprintf(stderr,"AUDIT_SIZE pe=%llu decls=%llu mir=%llu: a zero length or a length past the cap is a refusal\n",
              (unsigned long long)pe_bytes,(unsigned long long)decl_bytes,(unsigned long long)mir_bytes);
      CHECK(0,"the audit's three sizes are real and within the caps");
      audit_write_report(out_dir,report,MANY_REPORT);
      audit_write_status(out_dir,"FAIL\n");
    } else {
      /* THE OBSERVED NUMBERS, and they are the ones this run produced. The
       * THREE COUNTS ARE THE CLOSED MODE'S: the functions the program
       * declares, the ones the root module's main can reach, and the
       * declarations the emitted unit carries. They are zero in the normal
       * mode, which is what the normal mode's report says. */
      fprintf(stderr,"AUDIT_OK sources=%u source_bytes=%zu blob=%zu nodes=%llu scopes=%llu binds=%llu mir_records=%llu mir_bytes=%llu decls=%llu pe=%llu symbols=%llu relocs=%llu closed=%llu declared=%llu reachable=%llu emitted=%llu\n",
              loaded,source_bytes,at,(unsigned long long)pe_len[3],(unsigned long long)pe_len[4],
              (unsigned long long)pe_len[5],(unsigned long long)words[3],(unsigned long long)mir_bytes,
              (unsigned long long)decl_bytes,(unsigned long long)pe_bytes,
              (unsigned long long)report[7],(unsigned long long)report[11],
              (unsigned long long)closed,(unsigned long long)pe_len[7],
              (unsigned long long)pe_len[8],(unsigned long long)pe_len[9]);
      /* AND THE ARTEFACTS, in the directory the caller named. */
      int wrote=audit_write(out_dir,"audit.pe",pe_out,(size_t)pe_bytes);
      wrote&=audit_write(out_dir,"audit.mir",(const void *)words,(size_t)mir_bytes);
      wrote&=audit_write(out_dir,"audit.decls",(const void *)decls,(size_t)decl_bytes);
      wrote&=audit_write_report(out_dir,report,MANY_REPORT);
      wrote&=audit_write_status(out_dir,"OK\n");
      CHECK(wrote,"the audit artefacts are written");
    }
  }
  free(scratch);free(decls);free(pe_out);free(blob);
}
/* A MIR CAPACITY THE IMAGE BUILDER CANNOT HOLD.
 *
 * The builder refuses with ITS OWN code when the image it was given cannot
 * hold the program, and every refusal the lower states after that is a
 * CONSEQUENCE of it: a coercion that cannot see a value because the record
 * that holds the value was never written. The lower must therefore report the
 * builder's code and NOT the consequence, and nothing may come out of it.
 *
 * THIS IS THE ROW THAT PINS THE PRIORITY. Before it, the full audit answered
 * 971 -- a shape refusal in the middle of a program that was not malformed --
 * because the consequence overwrote the cause. */
static void run_capacity_refusal(const NovaHostImage *image,const struct Fixture *f,
                                 char *blob,uint64_t *spans,uint64_t *scratch,uint8_t *decls,
                                 uint8_t *pe_out,uint64_t *pe_len,uint64_t *report) {
  cases++;
  size_t blob_len=build_blob(f,blob,MANY_BLOB,spans);
  CHECK(blob_len>0,"the capacity fixture fits the blob");
  if(blob_len==0) return;
  for(unsigned i=0;i<MANY_REPORT;i++) report[i]=0;
  uint64_t code=call_many(image,blob,blob_len,spans,f->count,f->root,0,0,0,&SMALL_CAPS,MANY_TINY_MIR,scratch,decls,pe_out,pe_len,report,NULL);
  uint64_t exact=pe_len[6];
  fprintf(stderr,"MANY_CAPACITY code=%llu exact=%llu report=%llu pe=%llu decls=%llu\n",
          (unsigned long long)code,(unsigned long long)exact,(unsigned long long)report[2],
          (unsigned long long)pe_len[0],(unsigned long long)pe_len[1]);
  CHECK(exact!=0,"the image builder's capacity code is published");
  CHECK(code!=0,"a full image is a refusal and not a success");
  CHECK(code==exact,"the refusal carries the image builder's own code");
  CHECK(code!=MANY_E_AST,"the consequence did not overwrite the cause");
  CHECK(report[2]==exact,"the report carries the image builder's own code");
  CHECK(pe_len[0]==0,"a full image produced no PE");
  CHECK(pe_len[1]==0,"a full image produced no declarations");
}

/* ---- the width regressions: TWO EXECUTIONS AND TWO FIXED ANSWERS -----------*/
/* THE QUESTION.
 *
 * The FIXTURES above carry an `oracle` flag, and that flag is the C
 * reference's PARSE-ONLY checker: it says the sources are acceptable and it
 * says NOTHING about what the program answers. The rows below need an ANSWER,
 * so they RUN TWICE: once through the C SEED -- nova_compile_many_v2, the C
 * compiler, mapped by the host mapper and executed on the real ABI2 runtime --
 * and once through the NOVA PRODUCER -- the image under test, compiled to a PE
 * and executed on the same runtime. Both measurements are PRINTED, and both are
 * compared with the row's FIXED expectation and with each other.
 *
 * THE SHAPE IS THE COMPILER'S OWN, REDUCED. macro_expand.nova:610 reads
 *     if source[start+i]!=((word>>((i%8)*8))&255) { return false; }
 * where `source` is a buf<u8>, so the LEFT operand of the comparison is EIGHT
 * bits wide, and `word` is a u64, so the RIGHT operand is SIXTY FOUR bits
 * wide. A comparison widens its operands to a common width. A lower that
 * keeps the FIRST operand's width and pushes it down into the RIGHT operand's
 * own subexpressions gives the nested shift a width of eight bits, and the
 * shift's guard then refuses a count of eight with NV2_SHIFT (12).
 *
 * THE ROWS. R1 is that shape, in the order of the report. R2 is the same
 * program with the operands SWAPPED: it must answer the same thing, and the
 * pair is what makes a defect an ASYMMETRY and not a rule. R3 compares a u8
 * with a u64 and asks which way the width goes. R4 is the explicit cast: the
 * shift keeps the width of its own LEFT operand under the cast, and the cast
 * truncates afterwards. R5 and R6 are the guards that must STAY: a shift whose
 * LEFT operand is eight bits wide is refused when the count reaches eight,
 * and the count is the WHOLE count, not a truncated one. R7 is the division:
 * a divisor of 256 is not a divisor of zero, and a width that truncated the
 * divisor would raise a division by zero that C does not raise. */
static const char *const fx_r1_u8_ne_u64[] = {
  "module app;\n"
  "export fn main() -> u64 {\n"
  "  let b: buf<u8> = alloc(runtime(), 2);\n"
  "  b[0] = 65;\n"
  "  b[1] = 66;\n"
  "  let word: u64 = 16961;\n"
  "  let mut i: u64 = 0;\n"
  "  while i < 2 {\n"
  "    if b[i] != ((word >> ((i % 8) * 8)) & 255) { return 0; }\n"
  "    i = i + 1;\n"
  "  }\n"
  "  return 42;\n"
  "}\n"
};
/* R2: THE SAME PROGRAM WITH THE OPERANDS SWAPPED. The width now comes from the
 * RIGHT operand, so this row answers 42 on its own, and it is the control that
 * makes R1 an asymmetry rather than a rule. */
static const char *const fx_r2_u64_ne_u8[] = {
  "module app;\n"
  "export fn main() -> u64 {\n"
  "  let b: buf<u8> = alloc(runtime(), 2);\n"
  "  b[0] = 65;\n"
  "  b[1] = 66;\n"
  "  let word: u64 = 16961;\n"
  "  let mut i: u64 = 0;\n"
  "  while i < 2 {\n"
  "    if ((word >> ((i % 8) * 8)) & 255) != b[i] { return 0; }\n"
  "    i = i + 1;\n"
  "  }\n"
  "  return 42;\n"
  "}\n"
};
/* R3: THE WIDTH QUESTION WITHOUT A SHIFT. One is a u8 and 256 is a u64, and
 * one is less than 256 in every reading that widens; a reading that keeps the
 * first operand's width truncates 256 to zero and answers the other way. */
static const char *const fx_r3_u8_lt_u64[] = {
  "module app;\n"
  "export fn main() -> u64 {\n"
  "  let small: u8 = 1;\n"
  "  let big: u64 = 256;\n"
  "  if small < big { return 42; }\n"
  "  return 0;\n"
  "}\n"
};
/* R4: THE EXPLICIT CAST. The shift keeps the width of its own LEFT operand
 * under the cast, and the cast truncates AFTER the shift: 16961 >> 8 is 66,
 * and 66 is a u8. */
static const char *const fx_r4_cast_u8_shift[] = {
  "module app;\n"
  "export fn main() -> u64 {\n"
  "  let word: u64 = 16961;\n"
  "  let byte: u8 = u8(word >> 8);\n"
  "  return u64(byte);\n"
  "}\n"
};
/* R5: THE GUARD THAT MUST STAY. The LEFT operand is eight bits wide, so a
 * count of eight is out of range, and the program must report NV2_SHIFT (12)
 * and not answer a number. */
static const char *const fx_r5_u8_left_count_8[] = {
  "module app;\n"
  "export fn main() -> u64 {\n"
  "  let small: u8 = 5;\n"
  "  return u64(small >> 8);\n"
  "}\n"
};
/* R6: THE SAME GUARD WITH A COUNT THAT A TRUNCATION WOULD HIDE. 256 is out of
 * range for an eight bit LEFT operand, and the count is the WHOLE count: a
 * count truncated to eight bits would be zero, and the guard would let a
 * shift of zero through and answer 5. */
static const char *const fx_r6_u8_left_count_256[] = {
  "module app;\n"
  "export fn main() -> u64 {\n"
  "  let small: u8 = 5;\n"
  "  return u64(small >> u64(256));\n"
  "}\n"
};
/* R7: THE DIVISOR. A divisor of 256 is not a divisor of zero, and the
 * quotient of one by 256 is zero. The row exists because a width that
 * truncates the DIVISOR would turn 256 into zero and raise a division by zero
 * that C does not raise. */
static const char *const fx_r7_divisor_256[] = {
  "module app;\n"
  "export fn main() -> u64 {\n"
  "  return u64(u8(u64(1) / u64(256)));\n"
  "}\n"
};
/* R8: THE NATURAL TYPE OF AN ADDITION. Two u8 operands are added at EIGHT
 * bits: that is the type the front end annotates on the node (the wider of
 * its two operands) and the type the C reference computes (nova.c: the width
 * of an arithmetic result is the wider of its two operands), so 255 + 1 is 0
 * and not 256. The WIDENING to a u64 is the return's own, and it happens
 * after the addition. */
static const char *const fx_r8_u8_add_wraps[] = {
  "module app;\n"
  "export fn main() -> u64 {\n"
  "  let byte: u8 = u8(255) + u8(1);\n"
  "  return u64(byte);\n"
  "}\n"
};
/* R9: THE SIGNED WIDTHS. The helper takes an i8 and returns an i64, and the
 * two rows are the two ends of the signed range. The return of main is a
 * u64, so each answer is the SIGN-EXTENDED value read as an unsigned one:
 * -128 is 18446744073709551488 and -1 is 18446744073709551615. */
static const char *const fx_r9_i8_neg128[] = {
  "module app;\n"
  "fn helper(v: i8) -> i64 { return i64(v); }\n"
  "export fn main() -> u64 { return u64(helper(i8(-128))); }\n"
};
static const char *const fx_r9_i8_neg1[] = {
  "module app;\n"
  "fn helper(v: i8) -> i64 { return i64(v); }\n"
  "export fn main() -> u64 { return u64(helper(i8(-1))); }\n"
};
/* R10: A SIGNED LEFT OPERAND AND AN UNSIGNED COUNT. A shift's count may be
 * unsigned while the value it shifts is signed, and that is legal, so the
 * count keeps its own type: 256 is 256 at the guard, and the guard refuses it
 * because the LEFT operand is eight bits wide. The answer is the refusal
 * itself: no value, and NV2_SHIFT (12). */
static const char *const fx_r10_signed_left_count_256[] = {
  "module app;\n"
  "export fn main() -> u64 { return u64(i8(5) >> 256); }\n"
};
/* THE ROWS AND THEIR FIXED ANSWERS. `want` is the return value and `error` is
 * the runtime error, and BOTH paths must give that pair.
 *
 * R8 AND R9 CARRY THE C REFERENCE'S ANSWERS, and they are read off the C
 * reference's own rules: an addition is at the wider of its two operands'
 * widths (so R8 is 0), and a signed value that reaches a u64 is its bits
 * (so R9 is 18446744073709551488 and 18446744073709551615). The run PRINTS the
 * C seed's measured answer next to the fixed one, so a disagreement between
 * the two is visible in the output and not hidden in a constant. */
static const struct Fixture WIDTH_FIXTURES[] = {
  { fx_r1_u8_ne_u64,         1, 0, 42, 0, 0, 1 },
  { fx_r2_u64_ne_u8,         1, 0, 42, 0, 0, 1 },
  { fx_r3_u8_lt_u64,         1, 0, 42, 0, 0, 1 },
  { fx_r4_cast_u8_shift,     1, 0, 66, 0, 0, 1 },
  { fx_r5_u8_left_count_8,   1, 0,  0, NV2_SHIFT, 0, 1 },
  { fx_r6_u8_left_count_256, 1, 0,  0, NV2_SHIFT, 0, 1 },
  { fx_r7_divisor_256,       1, 0,  0, 0, 0, 1 },
  { fx_r8_u8_add_wraps,      1, 0,  0, 0, 0, 1 },
  { fx_r9_i8_neg128,         1, 0, UINT64_C(18446744073709551488), 0, 0, 1 },
  { fx_r9_i8_neg1,           1, 0, UINT64_C(18446744073709551615), 0, 0, 1 },
  { fx_r10_signed_left_count_256, 1, 0, 0, NV2_SHIFT, 0, 1 }
};
#define WIDTH_FIXTURE_N ((unsigned)(sizeof WIDTH_FIXTURES / sizeof WIDTH_FIXTURES[0]))
/* THE MEASURED ANSWER OF ONE PE, IN A BOUNDED CHILD. The parent's context is
 * copied into the child, so every refusal starts from an independent error
 * state, and the packet carries the return value with the context's error.
 * This is the observation `invoke_pe` makes, without the verdict: the rows
 * below compare TWO measurements, so both of them are read first. */
static int measure_pe(CallbackImage *pe,NovaContextV2 *ctx,uint64_t *result,uint64_t *error) {
  int fd[2];if(pipe(fd))return 0;
  pid_t pid=fork();
  if(pid==0) {
    alarm(5);close(fd[0]);uint64_t r=((Abi2Entry)pe->entry)(ctx,NULL,0);
    uint64_t packet[4]={r,ctx?ctx->error:0,ctx?ctx->error_source:0,ctx?ctx->error_offset:0};
    int ok=write(fd[1],packet,sizeof packet)==(ssize_t)sizeof packet;_exit(ok?0:3);
  }
  close(fd[1]);if(pid<0){close(fd[0]);return 0;}
  uint64_t packet[4]={0};ssize_t got=read(fd[0],packet,sizeof packet);close(fd[0]);
  int status=0;waitpid(pid,&status,0);
  if(!WIFEXITED(status)||WEXITSTATUS(status)!=0||got!=(ssize_t)sizeof packet)return 0;
  result[0]=packet[0];error[0]=packet[1];return 1;
}
/* THE C SEED'S ANSWER TO ONE FIXTURE. The C compiler compiles the SAME
 * sources the producer is given, its image is mapped by the host mapper that
 * is already exercised here, and the image is executed on the real ABI2
 * runtime. The answer is the C reference's, MEASURED and not asserted. */
static int measure_c_seed(const char *const *sources,unsigned count,uint64_t *result,uint64_t *error,
                           char *why,size_t wn) {
  NtFInput inputs[8];
  if(count>8) { snprintf(why,wn,"too many sources for the seed"); return 0; }
  for(unsigned i=0;i<count;i++) inputs[i]=(NtFInput){"regression.nova",sources[i],strlen(sources[i])};
  NtArtifact art={0};
  if(!nova_compile_many_v2(inputs,count,&art)) {
    snprintf(why,wn,"the C seed refuses the sources: E%u %zu:%zu %s",art.error.code,
            art.error.line,art.error.column,art.error.message);
    nt_artifact_free(&art);return 0;
  }
  NovaHostImage image={0};
  if(!nova_host_map(&art,&image)) {
    snprintf(why,wn,"the C seed's image does not map");
    nt_artifact_free(&art);return 0;
  }
  NovaContextV2 ctx={0};
  if(!nova_context_init_v2(&ctx)) {
    snprintf(why,wn,"the C seed's runtime does not initialize");
    nova_host_unmap(&image);nt_artifact_free(&art);return 0;
  }
  uint64_t got=image.entry(&ctx,NULL,0);
  uint64_t err=ctx.error;
  nova_context_destroy_v2(&ctx);
  nova_host_unmap(&image);
  nt_artifact_free(&art);
  result[0]=got;error[0]=err;return 1;
}
/* THE WIDTH REGRESSIONS, RUN. TWO PATHS, ONE FIXED EXPECTATION.
 *
 * The C SEED is the reference: it is compiled by the C compiler and executed
 * on the real runtime. The NOVA PRODUCER is the image under test: the same
 * sources go through the producer's own pipeline, and the PE it produces is
 * executed on the same runtime. The row is green when the two agree with the
 * fixed expectation, and the MEASUREMENTS are printed either way, because a
 * red row with no numbers measures nothing. */
static void run_width_regressions(const NovaHostImage *image,NovaContextV2 *ctx,
                                   char *blob,uint64_t *spans,uint64_t *scratch,uint8_t *decls,
                                   uint8_t *pe_out,uint64_t *pe_len,uint64_t *report) {
  for(unsigned i=0;i<WIDTH_FIXTURE_N;i++) {
    const struct Fixture *f=&WIDTH_FIXTURES[i];
    cases++;
    /* THE C REFERENCE'S OWN CHECKER, KEPT: it says the sources are
     * acceptable, and it is not the answer. */
    if(f->oracle) {
      NtFInput refs[8];
      for(unsigned k=0;k<f->count&&k<8;k++) refs[k]=(NtFInput){"regression.nova",f->sources[k],strlen(f->sources[k])};
      NtDiagnostic diag;memset(&diag,0,sizeof diag);
      int accepted=nova_check_many_v2(refs,f->count,&diag);
      if(!accepted) fprintf(stderr,"REGRESSION_CHECK row=%u code=%u line=%u column=%u\n",i,
                            (unsigned)diag.code,(unsigned)diag.line,(unsigned)diag.column);
      CHECK(accepted!=0,"the C reference's checker accepts the regression sources");
    }
    /* THE C SEED, RUN. */
    uint64_t seed_result=0,seed_error=0;char why[256]={0};
    int seeded=measure_c_seed(f->sources,f->count,&seed_result,&seed_error,why,sizeof why);
    if(!seeded) fprintf(stderr,"REGRESSION_SEED row=%u %s\n",i,why);
    CHECK(seeded!=0,"the C seed compiles and runs the regression sources");
    /* THE NOVA PRODUCER, RUN. */
    uint64_t native_result=0,native_error=0;int produced=0;
    size_t blob_len=build_blob(f,blob,MANY_BLOB,spans);
    CHECK(blob_len>0,"the regression fixture fits the blob");
    if(blob_len>0) {
      for(unsigned k=0;k<MANY_REPORT;k++) report[k]=0;
      uint64_t code=call_many(image,blob,blob_len,spans,f->count,f->root,0,0,0,&SMALL_CAPS,0,
                              scratch,decls,pe_out,pe_len,report,NULL);
      if(code!=0) {
        fprintf(stderr,"REGRESSION_PRODUCER row=%u code=%llu stage=%llu report=%llu/%llu/%llu/%llu\n",i,
                (unsigned long long)code,(unsigned long long)report[8],
                (unsigned long long)report[0],(unsigned long long)report[1],
                (unsigned long long)report[2],(unsigned long long)report[3]);
      } else {
        char pwhy[256]={0};CallbackImage pe={0};
        int rc=map_callback_pe(pe_out,(size_t)pe_len[0],&pe,pwhy,sizeof pwhy);
        if(rc) fprintf(stderr,"REGRESSION_MAP row=%u %s\n",i,pwhy);
        else {
          produced=measure_pe(&pe,ctx,&native_result,&native_error);
          munmap(pe.base,pe.size);
          if(!produced) fprintf(stderr,"REGRESSION_RUN row=%u the produced PE did not answer\n",i);
        }
      }
    }
    /* THE MEASUREMENTS, BOTH PATHS, AND THE FIXED EXPECTATION. */
    fprintf(stderr,"REGRESSION row=%u seed=(%llu,%llu) native=(%llu,%llu) want=(%llu,%llu)\n",i,
            (unsigned long long)seed_result,(unsigned long long)seed_error,
            (unsigned long long)native_result,(unsigned long long)native_error,
            (unsigned long long)f->want,(unsigned long long)f->error);
    CHECK(seed_result==f->want&&seed_error==f->error,
          "the C seed answers the regression row's fixed expectation");
    CHECK(produced!=0,"the producer's image runs");
    CHECK(native_result==f->want&&native_error==f->error,
          "the Nova producer answers the regression row's fixed expectation");
    CHECK(seed_result==native_result&&seed_error==native_error,
          "the Nova producer and the C seed answer the same thing");
    if(produced&&native_result==f->want&&native_error==f->error) abi_native++;
  }
}

int main(void){
  NtFInput inputs[PATHS_N+3];char *texts[PATHS_N+3]={0};size_t sizes[PATHS_N+3]={0};int all=1;
  /* PATHS[0] IS THE OLD ENTRY, AND IT EXPORTS A main. IT IS REPLACED BY THE
   * ENTRY BELOW, NOT COPIED: two exported mains in one artifact make the
   * entry ambiguous before a single RED row is measured. The count is the
   * closure minus that entry plus this one plus the three modules the many
   * path needs. */
  for(unsigned i=0;i<PATHS_N+3;i++) {
    const char *path=i==0?"tests/nova/tests/nova-machine-many-entry.nova"
                   :i<PATHS_N?PATHS[i]
                   :i==PATHS_N?"compiler/nova/frontend/nova_language_parse.nova"
                   :i==PATHS_N+1?"compiler/nova/backend/nova/nova_machine_many.nova"
                   :"compiler/nova/backend/nova/nova_machine_lower.nova";
    texts[i]=loadf(path,&sizes[i]);if(!texts[i])all=0;
    inputs[i]=(NtFInput){path,texts[i],sizes[i]};
  }
  NtArtifact art={0};NovaHostImage image={0};int context_ready=0;NovaContextV2 ctx={0};
  CHECK(all,"the many producer sources load");
  int compiled=all&&nova_compile_many_v2(inputs,PATHS_N+3,&art);
  CHECK(compiled,"the many producer compiles");
  if(!compiled){fprintf(stderr,"E%u %zu:%zu %s\n",art.error.code,art.error.line,art.error.column,art.error.message);goto cleanup;}
  CHECK(nova_host_map(&art,&image),"the many producer maps");
  if(!image.entry)goto cleanup;
  context_ready=nova_context_init_v2(&ctx);CHECK(context_ready,"the real ABI2 runtime initializes");
  if(!context_ready)goto cleanup;
  {
    uint64_t *scratch=(uint64_t *)malloc((size_t)(MANY_NODES+MANY_SIDES+MANY_BINDS+MANY_FIELDS+MANY_MODULES+MANY_MIR)*sizeof(uint64_t));
    char *blob=(char *)malloc(MANY_BLOB);
    uint8_t *pe_out=(uint8_t *)malloc(MANY_PE);
    uint8_t *decls=(uint8_t *)malloc(MANY_DECLS);
    uint64_t spans[160],pe_len[MANY_LENGTHS],report[MANY_REPORT];
    CHECK(scratch&&blob&&pe_out&&decls,"the many harness buffers allocated");
    if(scratch&&blob&&pe_out&&decls) {
      /* THE COUNTER THAT MEASURES THE UNIT IS MEASURED FIRST, on texts it
       * did not read a counter from. */
      count_function_controls();
      for(unsigned i=0;i<FIXTURE_N;i++) run_fixture(&image,&ctx,&FIXTURES[i],0,0,0,0,blob,spans,scratch,decls,pe_out,pe_len,report,NULL);
      for(unsigned i=0;i<ROOT_FIXTURE_N;i++) run_fixture(&image,&ctx,&ROOT_FIXTURES[i],MANY_E_ROOT,0,0,0,blob,spans,scratch,decls,pe_out,pe_len,report,NULL);
      /* THE CLOSED MODE'S ROWS: the same programs in the closed mode, the
       * root selection's own refusals in the closed mode, a program with a
       * big uncalled function measured before and after, and the same
       * program twice with the same PE. */
      run_closed_rows(&image,&ctx,blob,spans,scratch,decls,pe_out,pe_len,report);
      /* THE BATCH'S ROWS: two real objects out of one program, the range
       * refusals, and the counts the batch publishes. */
      run_batch_rows(&image,&ctx,blob,spans,scratch,decls,pe_out,pe_len,report);
      /* THE WIDTH REGRESSIONS: the C seed and the Nova producer, each RUN and
       * each MEASURED, compared with a fixed expectation and with each other. */
      run_width_regressions(&image,&ctx,blob,spans,scratch,decls,pe_out,pe_len,report);
      /* AN INVALID ROOT: the frontend refuses it, and the C reference has no
       * root parameter, so there is no oracle but the refusal itself. */
      cases++;
      size_t blob_len=build_blob(&FIXTURES[0],blob,MANY_BLOB,spans);
      CHECK(blob_len>0,"the invalid root fixture fits the blob");
      if(blob_len>0) {
        for(unsigned i=0;i<MANY_REPORT;i++) report[i]=0;
        uint64_t code=call_many(&image,blob,blob_len,spans,FIXTURES[0].count,99,0,0,0,&SMALL_CAPS,0,scratch,decls,pe_out,pe_len,report,NULL);
        CHECK(code!=0&&code!=MANY_FAULT,"the pipeline refuses an out of range root index");
        CHECK(pe_len[0]==0,"the refused root produced no PE");
      }
      /* A FULL IMAGE: the builder's own code, and nothing else. */
      run_capacity_refusal(&image,&FIXTURES[0],blob,spans,scratch,decls,pe_out,pe_len,report);
    }
    free(decls);free(pe_out);free(blob);free(scratch);
  }
  /* THE AUDIT, ONLY WHEN THE CALLER ASKS FOR IT. The list names the sources
   * and the directory names where the artefacts go; without both, the audit
   * does not run and the small fixtures are the whole gate.
   *
   * NOVA_NATIVE_CLOSED=1 PUTS THE AUDIT IN THE CLOSED APPLICATION MODE: the
   * compiler's own sources are a program whose main is the driver's, and the
   * closed mode emits the part of it that main can reach. The variable is
   * read HERE and nowhere else, and its absence is the normal mode. */
  {
    const char *list=getenv("NOVA_NATIVE_SOURCE_LIST");
    const char *mode=getenv("NOVA_NATIVE_CLOSED");
    uint64_t closed=(mode&&*mode&&strcmp(mode,"0")!=0)?1:0;
    if(list&&*list) {
      const char *out=getenv("NOVA_NATIVE_AUDIT_OUT");
      CHECK(out&&*out,"the audit output directory is named");
      if(out&&*out) run_audit(&image,list,out,closed);
    }
  }
cleanup:
  if(context_ready)CHECK(nova_context_destroy_v2(&ctx),"the real ABI2 runtime cleanup");
  nova_host_unmap(&image);nt_artifact_free(&art);
  for(unsigned i=0;i<PATHS_N+3;i++)free(texts[i]);
  printf("NTASM_NOVA_MACHINE_MANY checks=%u failures=%u cases=%u native=%u\n",checks,failures,cases,abi_native);
  return failures?1:0;
}
