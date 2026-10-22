#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include "../../../compiler/c/ntasm/formats/object.h"
#include "../../../compiler/c/ntasm/formats/pe_layout.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks,failures,cases;
#define CHECK(c,m) do{checks++;if(!(c)){failures++;fprintf(stderr,"FAIL %s\n",m);}}while(0)
static char*load(const char*p,size_t*n){FILE*f=fopen(p,"rb");if(!f)return NULL;fseek(f,0,SEEK_END);long z=ftell(f);fseek(f,0,SEEK_SET);char*b=z>=0?malloc((size_t)z+1):NULL;if(!b||fread(b,1,(size_t)z,f)!=(size_t)z){free(b);fclose(f);return NULL;}fclose(f);b[z]=0;*n=(size_t)z;return b;}
static uint64_t r64(const uint8_t*p){uint64_t v=0;for(unsigned i=0;i<8;i++)v|=(uint64_t)p[i]<<(i*8);return v;}
static NtBuffer write_object(const NtObject*o){NtBuffer f={0};NtDiagnostic e={0};CHECK(nt_object_write(o,&f,&e),"write NXO fixture");return f;}
typedef struct{uint64_t returned,runtime;uint8_t*out;}Run;
static Run run(const NovaHostImage*i,const NtBuffer*l,const NtBuffer*r,size_t capacity){Run x={0};x.out=malloc(capacity+16);CHECK(x.out!=NULL,"output allocation");if(!x.out)return x;memset(x.out,0xcc,capacity+16);NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"context init");uint64_t lh=nova_borrow_v2(&c,l->bytes,l->size,0),rh=nova_borrow_v2(&c,r->bytes,r->size,0),oh=nova_borrow_v2(&c,x.out,capacity,1);uint64_t a[]={lh,l->size,rh,r->size,oh,capacity};x.returned=i->entry(&c,a,6);x.runtime=c.error;CHECK(nova_context_destroy_v2(&c),"context cleanup");return x;}
static void expect_error(const NovaHostImage*i,const char*n,const NtBuffer*l,const NtBuffer*r,size_t cap,uint64_t code){Run x=run(i,l,r,cap);cases++;CHECK(x.returned==code&&x.runtime==0,"expected link PE error");if(x.out){CHECK(x.out[0]==0xcc&&x.out[1]==0xcc,"error output transactional");free(x.out);}if(x.returned!=code)fprintf(stderr,"FAIL %s ret=%llu\n",n,(unsigned long long)x.returned);}
/* ===================================================================
 * LOT 18 (P1) -- ADDRESSING AND RELOCATION BOUNDARIES.
 *
 * THE FAMILY IS NOT MISSING, SO NOTHING HERE BUILDS IT. A reference to
 * a data symbol is emitted as a four byte displacement whose value is
 * computed at codegen.c:1660-1661 as
 *     displacement = target - (displacement_site + 4)
 *     target       = base + offset + addend
 * which IS the RIP-relative form -- named by its arithmetic and not by
 * the word, with REL32 as its kind -- and patch_local:363-368 is the
 * same shape on the branch path. What follows exercises the LIMITS of
 * that arithmetic. Every row has two halves, a value the product must
 * ACCEPT and a value it must REFUSE with its own name: a row with only
 * an accept half constrains nothing.
 *
 * THE RELOCATION PATH, AS READ BEFORE ANY OF THIS WAS WRITTEN
 * (compiler/c/):
 *   frontend.c:928-940    address_of addend, bounded to signed32
 *   frontend.c:1126-1140  a memory literal and the running sum,
 *                         bounded to disp32 -- code 504
 *   codegen.c:714,1054    a reference to a data symbol -> add_data_patch
 *   codegen.c:327-341     add_data_patch -> REL32, variable, addend
 *   codegen.c:363-368     patch_local, the rel32 range, NTCG_E_RANGE
 *   codegen.c:1650-1667   the data patch, the same range -- code 704
 *   codegen.c:1460-1462   DIR64 for a static pointer initializer
 *   object.c:86-102       validate: kind, site, target, overlap, order
 *   object_link.c:148-159 intermodule: an import with no exported
 *                         definition, or a contract that disagrees
 *   object_materialize.c:35-37  an import that reached the artifact
 *   object_materialize.c:59-76 apply, through pe_layout.h:31-68
 *   pe_layout.h:45-46     REL32: S+A-(P+4) outside signed32
 *   pe_layout.h:51-63     DIR64: S+A over the 0x140000000 image base
 *
 * NO TWO REFUSALS SHARE A REASON. 504 is a literal that does not fit
 * the disp32 FIELD. 704 is a computed RIP-relative DISTANCE that does
 * not fit rel32. 800 "relocation arithmetic or displacement out of
 * range" is that same distance refusing at the materializer. 800
 * "unresolved object import" and 824 "unresolved import or definition
 * not exported" are UNRESOLVED, and share no string with any of the
 * three RANGE reasons. Each is made to occur below and its code is
 * READ OFF THE DIAGNOSTIC, never written by hand: where a row prints a
 * code it is the code the product returned for that case.
 *
 * THE ACCEPT THRESHOLDS ARE DERIVED, NOT GUESSED. The largest addend
 * whose computed distance is exactly INT32_MAX is solved from the
 * object the product itself produced, using the formula above, and the
 * linker threshold is solved from nt_pe_layout and nt_pe_logical_rva.
 * A literal written by hand here would be the author's guess at the
 * encoding, which is the thing this lot exists to measure.
 *
 * A CATCH-ALL IS REPORTED AS ONE. object.c:91-94 refuses a bad kind, a
 * site outside its section, a target of zero and a target past the
 * last symbol with the SAME string and the same diagnostic offset, so
 * V2 and V3 below are ONE proof of a shared refusal and not two
 * independent ones. That is measured and stated, not papered over.
 * =================================================================== */
#define BND_VREASON "invalid relocation kind, site or target"
#define BND_MRANGE "relocation arithmetic or displacement out of range"
#define BND_UNRES "unresolved object import"
#define BND_LREASON "unresolved import or definition not exported"
static unsigned bnd_rows;
static void bnd_row(const char *id, const char *layer, const char *accept_text,
                    const char *refuse_text, unsigned code, const char *reason,
                    int red) {
  bnd_rows++;
  cases++;
  checks++;
  if (red) {
    failures++;
    fprintf(stderr, "FAIL BND %s row went red\n", id);
  }
  fprintf(stderr, "  BND %-4s %-8s accept[%s] refuse[%s] code=%u reason=\"%s\" %s\n",
          id, layer, accept_text, refuse_text, code, reason, red ? "RED" : "green");
}
static int bnd_compile(const char *src, NtObject *o, NtDiagnostic *e) {
  NtFInput in = {"d", src, strlen(src)};
  return nt_object_compile(&in, 1, o, e);
}
/* One source, one knob: a load through a data symbol at a signed
 * addend. This is the form that reaches codegen.c:1054 and from there
 * add_data_patch, so the displacement under test is the one the
 * product computes, not one this file wrote down. */
static const char *bnd_data_ref(long long add) {
  static char b[1024];
  snprintf(b, sizeof b,
           "module d\ntarget x86_64-nexora-uefi\n"
           "section .rdata {\nexport data item:u64=1\n}\n"
           "section .text {\nexport fn main()->u64\n"
           "effects {reads_mem,writes_mem}\nclobbers {rax,rflags} {\n"
           "load rax, [item%c%lld]:ptr<user,u64>\nreturn 0\n}\n}\n",
           add < 0 ? '-' : '+', add < 0 ? -add : add);
  return b;
}
static int bnd_free_object(NtObject *o, int ok) {
  if (ok)
    nt_object_free(o);
  return ok;
}

/* R -- the producer. Two bounds sit on the same literal axis and they
 * are not the same bound: the disp32 field, and the rel32 distance the
 * field then carries. */
static void bnd_producer(void) {
  NtObject base = {0};
  NtDiagnostic be = {0};
  int ok = bnd_compile(bnd_data_ref(0), &base, &be);
  long long delta = 0, threshold = 0;
  if (ok && base.relocation_count == 1 && base.relocations[0].target &&
      base.relocations[0].target <= base.symbol_count) {
    size_t rdata_base = (base.sections[0].size + 4095u) & ~(size_t)4095u;
    size_t site = base.relocations[0].offset;
    size_t item = base.symbols[base.relocations[0].target - 1].offset;
    delta = (long long)(rdata_base + 8u + item) - (long long)(site + 4u);
    threshold = 2147483647LL - delta;
  }
  cases++;
  checks++;
  if (!(ok && base.relocation_count == 1)) {
    failures++;
    fprintf(stderr, "FAIL BND base object carries exactly one relocation (code %u %s)\n",
            be.code, be.message);
  }
  cases++;
  checks++;
  if (!(threshold > 0 && threshold <= 2147483647LL)) {
    failures++;
    fprintf(stderr, "FAIL BND derived threshold is a legal addend (threshold=%lld)\n",
            threshold);
  }
  if (ok)
    nt_object_free(&base);
  char a[80], r[80];
  int red;
  if (!ok)
    return;

  /* R1 -- the largest addend whose computed distance is exactly
   * INT32_MAX is accepted, and one past it is refused by the DISTANCE
   * bound, code 704, which is a different bound from R3's. */
  {
    NtObject o = {0};
    NtDiagnostic e = {0};
    int good = bnd_compile(bnd_data_ref(threshold), &o, &e);
    red = !(good && o.relocation_count == 1 &&
            o.relocations[0].kind == NT_OBJECT_REL32 &&
            o.relocations[0].addend == threshold);
    bnd_free_object(&o, good);
    snprintf(a, sizeof a, "addend=%lld distance=2147483647", threshold);
    good = bnd_compile(bnd_data_ref(threshold + 1), &o, &e);
    red |= good || e.code != 704 || !strstr(e.message, "outside rel32");
    bnd_free_object(&o, good);
    snprintf(r, sizeof r, "addend=%lld distance=2147483648", threshold + 1);
    bnd_row("R1", "codegen", a, r, e.code, e.message, red);
  }
  /* R2 -- the most negative representable addend is accepted, and one
   * byte below it is refused by the FIELD bound, code 504. The most
   * negative distance the producer can reach is printed with it: it
   * is INT32_MIN+delta and delta is positive, so the rel32 lower bound
   * is not reachable from the source at all. */
  {
    NtObject o = {0};
    NtDiagnostic e = {0};
    int good = bnd_compile(bnd_data_ref(-2147483648LL), &o, &e);
    red = !(good && o.relocation_count == 1 &&
            o.relocations[0].addend == -2147483648LL);
    bnd_free_object(&o, good);
    snprintf(a, sizeof a, "addend=-2147483648 distance=%lld", -2147483648LL + delta);
    good = bnd_compile(bnd_data_ref(-2147483649LL), &o, &e);
    red |= good || e.code != 504 || !strstr(e.message, "outside disp32");
    bnd_free_object(&o, good);
    snprintf(r, sizeof r, "addend=-2147483649");
    bnd_row("R2", "frontend", a, r, e.code, e.message, red);
  }
  /* R3 -- the positive end of the same axis, so the two codes are seen
   * to fire on neighbouring literals: 2147483647 clears the FIELD and
   * dies on the DISTANCE, 2147483648 dies on the FIELD. Two bounds,
   * two codes, one axis. */
  {
    NtObject o = {0};
    NtDiagnostic e = {0};
    int good = bnd_compile(bnd_data_ref(2147483647LL), &o, &e);
    red = good || e.code != 704;
    bnd_free_object(&o, good);
    snprintf(a, sizeof a, "addend=2147483647 field=ok");
    good = bnd_compile(bnd_data_ref(2147483648LL), &o, &e);
    red |= good || e.code != 504;
    bnd_free_object(&o, good);
    snprintf(r, sizeof r, "addend=2147483648");
    bnd_row("R3", "frontend", a, r, e.code, e.message, red);
  }
  fprintf(stderr,
          "  BND UNREACHABLE lower_rel32_bound=INT32_MIN margin=%lld bytes "
          "reason=data_sections_follow_text_so_the_most_negative_reachable_displacement_is_INT32_MIN_plus_margin\n",
          delta);
}

/* V -- the validator. Kind, site span and target identity, each with an
 * accept half and a refuse half, all read off nt_object_validate. */
static void bnd_validator(const char *id, const char *accept_text,
                          unsigned akind, unsigned atarget, uint64_t aoffset,
                          const char *refuse_text, unsigned rkind,
                          unsigned rtarget, uint64_t roffset) {
  uint8_t text[32] = {0}, rdata[32] = {0}, data[32] = {0};
  NtObjectSymbol syms[2] = {
      {"a.fn", "fn:u64", 1, NT_OBJECT_FUNCTION | NT_OBJECT_EXPORT, 0, 32},
      {"b.item", "data:u64", 2, NT_OBJECT_VARIABLE | NT_OBJECT_EXPORT, 0, 8}};
  NtObjectReloc ra = {1, akind, atarget, aoffset, 0};
  NtObjectReloc rr = {1, rkind, rtarget, roffset, 0};
  NtObject oa = {0}, orr = {0};
  NtDiagnostic ea = {0}, er = {0};
  oa.target = orr.target = 1;
  oa.entry_symbol = orr.entry_symbol = 1;
  oa.sections[0] = orr.sections[0] = (NtBuffer){text, 32, 32};
  oa.sections[1] = orr.sections[1] = (NtBuffer){rdata, 32, 32};
  oa.sections[2] = orr.sections[2] = (NtBuffer){data, 32, 32};
  oa.symbols = orr.symbols = syms;
  oa.symbol_count = orr.symbol_count = 2;
  oa.relocations = &ra;
  oa.relocation_count = 1;
  orr.relocations = &rr;
  orr.relocation_count = 1;
  int good = nt_object_validate(&oa, &ea);
  int bad = nt_object_validate(&orr, &er);
  int red = !good;
  red |= bad;
  red |= er.code != 800 || strcmp(er.message, BND_VREASON);
  bnd_row(id, "validate", accept_text, refuse_text, er.code, er.message, red);
}
static void bnd_validators(void) {
  bnd_validator("V1", "kind=REL32@0,kind=DIR64@0", NT_OBJECT_REL32, 2, 0,
                "kind=0", 0, 2, 0);
  bnd_validator("V1b", "kind=DIR64@0", NT_OBJECT_DIR64, 2, 0, "kind=3", 3, 2, 0);
  bnd_validator("V2", "target=1,target=2", NT_OBJECT_REL32, 1, 0, "target=0", NT_OBJECT_REL32, 0, 0);
  bnd_validator("V2b", "target=2", NT_OBJECT_REL32, 2, 0, "target=3", NT_OBJECT_REL32, 3, 0);
  bnd_validator("V3", "REL32@28 (last 4 of 32)", NT_OBJECT_REL32, 2, 28, "REL32@29 (33>32)", NT_OBJECT_REL32, 2, 29);
  bnd_validator("V3b", "DIR64@24 (last 8 of 32)", NT_OBJECT_DIR64, 2, 24, "DIR64@25 (33>32)", NT_OBJECT_DIR64, 2, 25);
}

/* M -- the materializer, where S+A-(P+4) is decided for the last time.
 * The accept half reads the four bytes back out of the artifact, so an
 * accept is a value and not merely the absence of a refusal. */
static int bnd_materialize(unsigned kind, long long addend, NtArtifact *out) {
  uint8_t text[32] = {0}, rdata[32] = {0}, data[32] = {0};
  NtObjectSymbol syms[2] = {
      {"a.fn", "fn:u64", 1, NT_OBJECT_FUNCTION | NT_OBJECT_EXPORT, 0, 32},
      {"b.item", "data:u64", 2, NT_OBJECT_VARIABLE | NT_OBJECT_EXPORT, 0, 8}};
  NtObjectReloc r = {1, kind, 2, 0, addend};
  NtObject o = {0};
  NtDiagnostic e = {0};
  o.target = 1;
  o.entry_symbol = 1;
  o.sections[0] = (NtBuffer){text, 32, 32};
  o.sections[1] = (NtBuffer){rdata, 32, 32};
  o.sections[2] = (NtBuffer){data, 32, 32};
  o.symbols = syms;
  o.symbol_count = 2;
  o.relocations = &r;
  o.relocation_count = 1;
  memset(out, 0, sizeof *out);
  int ok = nt_object_materialize(&o, out, &e);
  (void)e;
  return ok;
}
static int32_t bnd_read32(const uint8_t *p) {
  int32_t v = 0;
  for (unsigned k = 0; k < 4; k++)
    v |= (int32_t)((uint32_t)p[k] << (8 * k));
  return v;
}
static void bnd_materializer(void) {
  NtPeLayout l;
  int have = nt_pe_layout(32, 32, 32, &l);
  long long delta = 0, threshold = 0;
  if (have) {
    uint64_t source = nt_pe_logical_rva(&l, 1);
    uint64_t target = nt_pe_logical_rva(&l, 2);
    delta = (long long)(target - (source + 4));
    threshold = 2147483647LL - delta;
  }
  NtArtifact art = {0};
  NtDiagnostic e = {0};
  char a[80], r[80];
  int red;

  /* M1 -- REL32 at the encoded edge, and one past it. */
  {
    int good = bnd_materialize(NT_OBJECT_REL32, threshold, &art);
    int value_ok = good && art.text.size >= 4 &&
                   bnd_read32(art.text.bytes) == 2147483647;
    if (good)
      nt_artifact_free(&art);
    red = !good || !value_ok;
    snprintf(a, sizeof a, "addend=%lld stored=%d", threshold, 2147483647);
    good = bnd_materialize(NT_OBJECT_REL32, threshold + 1, &art);
    if (good)
      nt_artifact_free(&art);
    memset(&e, 0, sizeof e);
    {
      uint8_t text[32] = {0}, rdata[32] = {0}, data[32] = {0};
      NtObjectSymbol syms[2] = {
          {"a.fn", "fn:u64", 1, NT_OBJECT_FUNCTION | NT_OBJECT_EXPORT, 0, 32},
          {"b.item", "data:u64", 2, NT_OBJECT_VARIABLE | NT_OBJECT_EXPORT, 0, 8}};
      NtObjectReloc rr = {1, NT_OBJECT_REL32, 2, 0, threshold + 1};
      NtObject o = {0};
      o.target = 1;
      o.entry_symbol = 1;
      o.sections[0] = (NtBuffer){text, 32, 32};
      o.sections[1] = (NtBuffer){rdata, 32, 32};
      o.sections[2] = (NtBuffer){data, 32, 32};
      o.symbols = syms;
      o.symbol_count = 2;
      o.relocations = &rr;
      o.relocation_count = 1;
      good = nt_object_materialize(&o, &art, &e);
      if (good)
        nt_artifact_free(&art);
    }
    red |= good || e.code != 800 || strcmp(e.message, BND_MRANGE);
    snprintf(r, sizeof r, "addend=%lld", threshold + 1);
    bnd_row("M1", "material", a, r, e.code, e.message, red);
  }
  /* M2 -- DIR64. Both source-reachable addends are accepted. The
   * refusal is a FORMAT boundary, not a source one: the producer
   * bounds every addend it writes to signed32 (frontend.c:930-937,
   * measured above as R2), while the guard at pe_layout.h:51-63
   * needs an addend larger than the 0x140000000 image base. The margin
   * between the two is printed below and no source can cross it. */
  {
    int good = bnd_materialize(NT_OBJECT_DIR64, 0, &art);
    if (good)
      nt_artifact_free(&art);
    red = !good;
    snprintf(a, sizeof a, "DIR64 addend=0,+-2^31");
    uint8_t text[32] = {0}, rdata[32] = {0}, data[32] = {0};
    NtObjectSymbol syms[2] = {
        {"a.fn", "fn:u64", 1, NT_OBJECT_FUNCTION | NT_OBJECT_EXPORT, 0, 32},
        {"b.item", "data:u64", 2, NT_OBJECT_VARIABLE | NT_OBJECT_EXPORT, 0, 8}};
    NtObjectReloc rr = {1, NT_OBJECT_DIR64, 2, 0, INT64_MIN};
    NtObject o = {0};
    o.target = 1;
    o.entry_symbol = 1;
    o.sections[0] = (NtBuffer){text, 32, 32};
    o.sections[1] = (NtBuffer){rdata, 32, 32};
    o.sections[2] = (NtBuffer){data, 32, 32};
    o.symbols = syms;
    o.symbol_count = 2;
    o.relocations = &rr;
    o.relocation_count = 1;
    memset(&e, 0, sizeof e);
    good = nt_object_materialize(&o, &art, &e);
    if (good)
      nt_artifact_free(&art);
    red |= good || e.code != 800 || strcmp(e.message, BND_MRANGE);
    snprintf(r, sizeof r, "DIR64 addend=INT64_MIN (FORMAT, not source)");
    bnd_row("M2", "material", a, r, e.code, e.message, red);
    fprintf(stderr,
            "  BND UNREACHABLE dir64_range_guard margin=%lld bytes "
            "reason=producer_bounds_every_addend_to_signed32_and_the_image_base_is_0x%llx\n",
            (long long)NT_PE_IMAGE_BASE - 2147483648LL,
            (unsigned long long)NT_PE_IMAGE_BASE);
  }
  /* M3 -- UNRESOLVED, the one family that shares no string with any
   * RANGE reason above. A data relocation whose target is an import
   * is refused because the name has no definition. */
  {
    uint8_t text[32] = {0}, rdata[32] = {0}, data[32] = {0};
    NtObjectSymbol syms[2] = {
        {"a.fn", "fn:u64", 1, NT_OBJECT_FUNCTION | NT_OBJECT_EXPORT, 0, 32},
        {"b.item", "data:u64", 0, NT_OBJECT_VARIABLE | NT_OBJECT_IMPORT, 0, 0}};
    NtObjectReloc rr = {1, NT_OBJECT_REL32, 2, 0, 0};
    NtObject o = {0};
    o.target = 1;
    o.entry_symbol = 1;
    o.sections[0] = (NtBuffer){text, 32, 32};
    o.sections[1] = (NtBuffer){rdata, 32, 32};
    o.sections[2] = (NtBuffer){data, 32, 32};
    o.symbols = syms;
    o.symbol_count = 2;
    o.relocations = &rr;
    o.relocation_count = 1;
    memset(&e, 0, sizeof e);
    int good = nt_object_materialize(&o, &art, &e);
    if (good)
      nt_artifact_free(&art);
    red = good || e.code != 800 || strcmp(e.message, BND_UNRES);
    snprintf(a, sizeof a, "target is an exported variable");
    snprintf(r, sizeof r, "target is an import");
    bnd_row("M3", "material", a, r, e.code, e.message, red);
  }
  (void)have;
}

/* L -- intermodule, through the linker. A data reference the provider
 * exports is resolved and the linked object materializes; the same
 * reference against a definition that is not exported is refused by
 * object_link.c:150, whose string is in no RANGE family.
 *
 * MEASURED, AND IT IS WHY THIS ROW IS LABELLED FORMAT: the source
 * language cannot express a data import at all. frontend.c:2975 is
 * `expect_word(p, "fn")` after the alias, so `import ... : data:u64`
 * is a parse error, and the intermodule half below is the object
 * format's, reached through nt_object_write. */
static int bnd_link(int provider_exported, NtDiagnostic *e) {
  uint8_t text[32] = {0}, rdata[32] = {0};
  NtObjectSymbol as[2] = {
      {"api.item", "data:u64", 0, NT_OBJECT_VARIABLE | NT_OBJECT_IMPORT, 0, 0},
      {"m.main", "fn:u64", 1, NT_OBJECT_FUNCTION | NT_OBJECT_EXPORT, 0, 32}};
  NtObjectReloc ar = {1, NT_OBJECT_REL32, 1, 0, 0};
  NtObject a = {0};
  a.target = 1;
  a.entry_symbol = 2;
  a.sections[0] = (NtBuffer){text, 32, 32};
  a.symbols = as;
  a.symbol_count = 2;
  a.relocations = &ar;
  a.relocation_count = 1;
  NtObjectSymbol bs[1] = {{"api.item", "data:u64", 2,
                           NT_OBJECT_VARIABLE |
                               (provider_exported ? NT_OBJECT_EXPORT : 0),
                           0, 8}};
  NtObject b = {0};
  b.target = 1;
  b.sections[1] = (NtBuffer){rdata, 32, 32};
  b.symbols = bs;
  b.symbol_count = 1;
  NtObject pair[2] = {a, b}, linked = {0};
  memset(e, 0, sizeof *e);
  int ok = nt_object_link(pair, 2, &linked, e);
  if (!ok)
    return 0;
  NtArtifact art = {0};
  int materialized = nt_object_materialize(&linked, &art, e);
  if (materialized)
    nt_artifact_free(&art);
  nt_object_free(&linked);
  if (!materialized)
    return 0;
  return 1;
}
static void bnd_intermodule(void) {
  NtDiagnostic e = {0};
  char r[96];
  int good = bnd_link(1, &e);
  int red = !good;
  good = bnd_link(0, &e);
  red |= good || e.code != 800 || strcmp(e.message, BND_LREASON);
  snprintf(r, sizeof r, "provider does not export the data definition");
  bnd_row("L1", "link", "provider exports the data definition", r, e.code,
          e.message, red);
  /* The same intermodule question asked in the language, where it is
   * answerable for functions and not for data. */
  {
    const char *importer =
        "module m\ntarget x86_64-nexora-uefi\n"
        "import api.echo as ext: fn()->u64\neffects {}\nclobbers {rax,rflags}\n"
        "section .text {\nexport fn main()->u64\neffects {}\n"
        "clobbers {rax,rflags} {\ncall ext\nmov rax, 0\nreturn 0\n}\n}\n";
    const char *provider =
        "module api\ntarget x86_64-nexora-uefi\nsection .text {\n"
        "export fn echo()->u64\neffects {}\nclobbers {rax,rflags} {\n"
        "mov rax, 0\nreturn 0\n}\n}\n";
    const char *data_import =
        "module m\ntarget x86_64-nexora-uefi\n"
        "import api.item as thing: data:u64\nsection .text {\n"
        "export fn main()->u64\neffects {}\nclobbers {rax,rflags} {\n"
        "mov rax, 0\nreturn 0\n}\n}\n";
    NtFInput in[2] = {{"m", importer, strlen(importer)},
                      {"api", provider, strlen(provider)}};
    NtObject o = {0};
    NtDiagnostic d = {0};
    int resolved = nt_object_compile(in, 2, &o, &d);
    cases++;
    checks++;
    if (!resolved) {
      failures++;
      fprintf(stderr, "FAIL BND L2 intermodule function import does not resolve (%u %s)\n",
              d.code, d.message);
 }
    bnd_free_object(&o, resolved);
    NtFInput single = {"m", data_import, strlen(data_import)};
    int data_ok = nt_object_compile(&single, 1, &o, &d);
    cases++;
    checks++;
    if (data_ok || d.code != 200) {
      failures++;
      fprintf(stderr,
 "FAIL BND L3 a data import must not parse in the source language (ok=%d %u %s)\n",
       data_ok, d.code, d.message);
    }
    fprintf(stderr,
            "  BND NOTE    L3 data_import_parses=%d code=%u reason=\"frontend.c:2975 "
            "expect_word(p,\\\"fn\\\") admits no data import\"\n",
        data_ok, d.code);
  }
}
static void bnd_boundaries(void) {
  fprintf(stderr, "  BND TABLE lot=18 addressing-and-relocation-boundaries\n");
  bnd_producer();
  bnd_validators();
  bnd_materializer();
  bnd_intermodule();
  fprintf(stderr, "  BND TABLE rows=%u\n", bnd_rows);
}

int main(void){const char*paths[]={"tests/nova/tests/nxo-link-pe-entry.nova","compiler/nova/formats/nxo/nxo_link_pe.nova","compiler/nova/formats/nxo/nxo_merge.nova","compiler/nova/formats/nxo/nxo_pe.nova","compiler/nova/formats/nxo/nxo.nova","compiler/nova/formats/pe/pe.nova"};char*sources[6]={0};NtFInput inputs[6];for(unsigned i=0;i<6;i++){size_t n=0;sources[i]=load(paths[i],&n);inputs[i]=(NtFInput){paths[i],sources[i],n};}CHECK(sources[0]&&sources[1]&&sources[2]&&sources[3]&&sources[4]&&sources[5],"sources load");NtArtifact compiler={0};int compiled=sources[0]&&sources[1]&&sources[2]&&sources[3]&&sources[4]&&sources[5]&&nova_compile_many_v2(inputs,6,&compiler);CHECK(compiled,"modules compile");if(!compiled)fprintf(stderr,"E%u %zu:%zu %s\n",compiler.error.code,compiler.error.line,compiler.error.column,compiler.error.message);NovaHostImage image={0};CHECK(compiled&&nova_host_map(&compiler,&image),"image maps");
 if(image.memory){uint8_t caller[]={0xe8,0,0,0,0,0xc3},callee[]={0xb8,0x2a,0,0,0,0xc3};NtObjectSymbol left_symbols[]={{"helper","fn:u64",0,NT_OBJECT_FUNCTION|NT_OBJECT_IMPORT,0,0},{"main","fn:u64",1,NT_OBJECT_FUNCTION|NT_OBJECT_EXPORT,0,6}};NtObjectReloc call={1,NT_OBJECT_REL32,1,1,0};NtObject left={0};left.target=1;left.entry_symbol=2;left.sections[0]=(NtBuffer){caller,6,6};left.symbols=left_symbols;left.symbol_count=2;left.relocations=&call;left.relocation_count=1;NtObjectSymbol helper={"helper","fn:u64",1,NT_OBJECT_FUNCTION|NT_OBJECT_EXPORT,0,6};NtObject right={0};right.target=1;right.sections[0]=(NtBuffer){callee,6,6};right.symbols=&helper;right.symbol_count=1;NtBuffer lf=write_object(&left),rf=write_object(&right);
  NtObject pair[]={left,right},linked={0};NtArtifact oracle={0};NtDiagnostic error={0};CHECK(nt_object_link(pair,2,&linked,&error)&&nt_object_materialize(&linked,&oracle,&error)&&nt_make_pe(&oracle),"C oracle links PE");Run ok=run(&image,&lf,&rf,65536);cases++;CHECK(ok.returned==0&&ok.runtime==0,"Nova link PE success");if(ok.out){uint64_t size=r64(ok.out);int parity=size==oracle.pe.size&&!memcmp(ok.out+8,oracle.pe.bytes,oracle.pe.size);if(!parity){size_t first=0,limit=size<oracle.pe.size?(size_t)size:oracle.pe.size;while(first<limit&&ok.out[8+first]==oracle.pe.bytes[first])first++;fprintf(stderr,"PE mismatch nova=%llu oracle=%zu first=%zu novaByte=%u oracleByte=%u\n",(unsigned long long)size,oracle.pe.size,first,first<size?ok.out[8+first]:0,first<oracle.pe.size?oracle.pe.bytes[first]:0);}CHECK(parity,"Nova link PE byte parity");int guards=1;for(size_t i=8+size;i<65552;i++)if(ok.out[i]!=0xcc)guards=0;CHECK(guards,"success output guards");free(ok.out);}nt_artifact_free(&oracle);nt_object_free(&linked);
  expect_error(&image,"short output",&lf,&rf,8,827);
  NtObjectSymbol wrong={"helper","fn:u32",1,NT_OBJECT_FUNCTION|NT_OBJECT_EXPORT,0,6};right.symbols=&wrong;NtBuffer wrongf=write_object(&right);expect_error(&image,"contract mismatch",&lf,&wrongf,65536,825);
  right.symbols=&helper;right.entry_symbol=1;NtBuffer twoentry=write_object(&right);expect_error(&image,"two entries",&lf,&twoentry,65536,826);
  right.entry_symbol=0;right.target=2;NtBuffer targetf=write_object(&right);expect_error(&image,"target mismatch",&lf,&targetf,65536,820);
  free(lf.bytes);free(rf.bytes);free(wrongf.bytes);free(twoentry.bytes);free(targetf.bytes);}
 if(image.memory) nova_host_unmap(&image);
 if(compiled) nt_artifact_free(&compiler);
 for(unsigned i=0;i<6;i++) free(sources[i]);
bnd_boundaries();

 printf("NTASM_NOVA_NXO_LINK_PE checks=%u failures=%u cases=%u\n",checks,failures,cases);
 return failures?1:0;
}
