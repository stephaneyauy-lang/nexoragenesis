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
static const uint8_t guard=0xcc;
static char*load(const char*p,size_t*n){FILE*f=fopen(p,"rb");if(!f)return NULL;fseek(f,0,SEEK_END);long z=ftell(f);fseek(f,0,SEEK_SET);char*b=z>=0?malloc((size_t)z+1):NULL;if(!b||fread(b,1,(size_t)z,f)!=(size_t)z){free(b);fclose(f);return NULL;}fclose(f);b[z]=0;*n=(size_t)z;return b;}
static uint64_t r64(const uint8_t*p){uint64_t v=0;for(unsigned i=0;i<8;i++)v|=(uint64_t)p[i]<<(i*8);return v;}
static NtBuffer make_object(uint32_t target,const uint8_t*t,size_t tn,const uint8_t*r,size_t rn,const uint8_t*d,size_t dn,int symbol){NtObject o={0};o.target=target;o.sections[0]=(NtBuffer){(uint8_t*)t,tn,tn};o.sections[1]=(NtBuffer){(uint8_t*)r,rn,rn};o.sections[2]=(NtBuffer){(uint8_t*)d,dn,dn};NtObjectSymbol s={"entry","fn:u64",1,NT_OBJECT_FUNCTION,0,tn};if(symbol){o.symbols=&s;o.symbol_count=1;o.entry_symbol=1;}NtBuffer file={0};NtDiagnostic e={0};CHECK(nt_object_write(&o,&file,&e),"oracle writes NXO");return file;}
typedef struct{uint64_t returned,runtime;uint8_t out[2048];}Run;
static Run run(const NovaHostImage*i,const NtBuffer*l,uint64_t ln,const NtBuffer*r,uint64_t rn,uint64_t outn){Run x={0};memset(x.out,guard,sizeof(x.out));NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"context init");uint64_t lh=nova_borrow_v2(&c,l->bytes,ln,0),rh=nova_borrow_v2(&c,r->bytes,rn,0),oh=nova_borrow_v2(&c,x.out,outn,1);uint64_t a[]={lh,ln,rh,rn,oh,outn};x.returned=i->entry(&c,a,6);x.runtime=c.error;CHECK(nova_context_destroy_v2(&c),"context cleanup");return x;}
static void expect_error(const NovaHostImage*i,const char*n,const NtBuffer*l,uint64_t ln,const NtBuffer*r,uint64_t rn,uint64_t outn,uint64_t code){Run x=run(i,l,ln,r,rn,outn);cases++;checks++;if(x.returned!=code||x.runtime||x.out[0]!=guard||x.out[1]!=guard){failures++;fprintf(stderr,"FAIL error %s ret=%llu runtime=%llu\n",n,(unsigned long long)x.returned,(unsigned long long)x.runtime);}}
/* object_link.c:78-84 gives every unit a base of align16(running total) for
 * every section, unconditionally, so a section that is empty still rounds the
 * running total up to 16. The shapes below are the ones where "align only when
 * the section is non empty" and "align rdata and data to 8" would each produce a
 * different merged image, and object_link.c is the oracle for all of them. */
typedef struct{const char*name;size_t lt,lr,ld,rt,rr,rd;unsigned sym;} Shape;
static NtBuffer plain_object(size_t tn,const uint8_t*t,size_t rn,const uint8_t*r,size_t dn,const uint8_t*d){NtObject o={0};o.target=1;o.sections[0]=(NtBuffer){(uint8_t*)t,tn,tn};o.sections[1]=(NtBuffer){(uint8_t*)r,rn,rn};o.sections[2]=(NtBuffer){(uint8_t*)d,dn,dn};NtBuffer file={0};NtDiagnostic e={0};int ok=nt_object_write(&o,&file,&e);CHECK(ok,"oracle writes plain NXO");if(!ok)fprintf(stderr,"E plain %s\n",e.message);return file;}
static NtBuffer sized_object(size_t tn,size_t rn,size_t dn,unsigned sym){NtObject o={0};NtObjectSymbol s={"p.q","d:u8",sym,NT_OBJECT_VARIABLE|NT_OBJECT_EXPORT,0,1};uint8_t*raw[3]={0};size_t want[3]={tn,rn,dn};o.target=1;for(unsigned k=0;k<3;k++)if(want[k]){raw[k]=malloc(want[k]);CHECK(raw[k]!=NULL,"shape payload allocation");if(raw[k])memset(raw[k],(int)(0x11*(k+1)),want[k]);o.sections[k]=(NtBuffer){raw[k],want[k],want[k]};}if(sym){o.symbols=&s;o.symbol_count=1;}NtBuffer file={0};NtDiagnostic e={0};int ok=nt_object_write(&o,&file,&e);CHECK(ok,"oracle writes shape NXO");if(!ok)fprintf(stderr,"E shape %s\n",e.message);for(unsigned k=0;k<3;k++)free(raw[k]);return file;}
/* One alignment probe, oracle compared end to end: the pairwise Nova merge runs
 * on two oracle written units, object_link.c links the same two units, and the
 * three merged section sizes are printed from both sides so a divergence shows
 * up as numbers and not only as a byte diff. */
static void probe_shape(const NovaHostImage*i,const Shape*s){NtBuffer left=sized_object(s->lt,s->lr,s->ld,0),right=sized_object(s->rt,s->rr,s->rd,s->sym);Run x=run(i,&left,left.size,&right,right.size,sizeof x.out);cases++;uint64_t size=x.returned==0?r64(x.out):0;NtObject inputs[2]={{0}},linked={0},merged={0};NtBuffer oracle={0};NtDiagnostic e={0};int ok=x.returned==0&&x.runtime==0;if(ok)ok=nt_object_read(left.bytes,left.size,&inputs[0],&e);if(ok)ok=nt_object_read(right.bytes,right.size,&inputs[1],&e);if(ok)ok=nt_object_link(inputs,2,&linked,&e);if(ok)ok=nt_object_write(&linked,&oracle,&e);if(ok)ok=size>0&&size+8<=sizeof x.out&&nt_object_read(x.out+8,size,&merged,&e);int parity=ok&&size==oracle.size&&!memcmp(x.out+8,oracle.bytes,oracle.size);fprintf(stderr,"ALIGN %-30s nova=%llu,%llu,%llu oracle=%zu,%zu,%zu %s\n",s->name,(unsigned long long)merged.sections[0].size,(unsigned long long)merged.sections[1].size,(unsigned long long)merged.sections[2].size,linked.sections[0].size,linked.sections[1].size,linked.sections[2].size,parity?"match":"DIVERGE");CHECK(parity,"alignment shape matches the C oracle");nt_object_free(&merged);free(oracle.bytes);nt_object_free(&linked);nt_object_free(&inputs[0]);nt_object_free(&inputs[1]);free(left.bytes);free(right.bytes);}
/* Shapes that separate the unconditional align16 of object_link.c:78 from the
 * two weaker rules. A right hand empty section is the `if size` case, a left
 * total of 8 or a right size that is a multiple of 8 but not of 16 is the
 * 8 versus 16 case, and the two trailing shapes carry a symbol so the rebased
 * offset is compared as well as the section size. */
static const Shape SHAPES[]={
 {"R.text empty, L.text=2",2,1,1,0,0,0,0},
 {"R.text empty, L.text=8",8,1,1,0,0,0,0},
 {"R.text empty, L.text=17",17,1,1,0,0,0,0},
 {"R.rdata empty, L.rdata=8",1,8,1,1,0,1,0},
 {"R.rdata empty, L.rdata=1",1,1,1,1,0,1,0},
 {"R.data empty, L.data=3",1,1,3,1,1,0,0},
 {"R.data empty, L.data=8",1,1,8,1,1,0,0},
 {"R all sections empty",1,1,1,0,0,0,0},
 {"R.rdata=8, multiple of 8",1,8,1,1,8,1,0},
 {"R.rdata=24, multiple of 8",1,8,1,1,24,1,0},
 {"L all sections empty",0,0,0,5,7,3,0},
 {"L and R all empty",0,0,0,0,0,0,0},
 {"L.text=16 already aligned",16,1,1,0,0,0,0},
 {"L 10,20,12 then R 3,9,7",10,20,12,3,9,7,0},
 {"R.rdata sym, L.rdata=8",1,8,1,1,8,1,2},
 {"R.data sym, L.data=3",1,1,3,1,1,3,3},
};
/* The 64MiB boundary of object_link.c:86. The three merged totals are compared
 * with a strict >, so a payload of exactly 64MiB is accepted and 64MiB+1 is
 * refused. Every single section total stays at or under 64MiB in both cases, so
 * only the aggregate cap can decide. The accept side cannot be byte compared: a
 * 64MiB merged object fits no out buffer, so the witness is that merge reached
 * the emit step and refused for want of room (822) while the C oracle accepted
 * the very same pair. */
static void boundary_case(const NovaHostImage*i,const char*n,const NtBuffer*l,const NtBuffer*r,int want_accept,size_t t,size_t r1,size_t d,size_t want_sum){NtObject*objs=calloc(2,sizeof*objs);NtObject linked={0};NtDiagnostic e={0};int ok=nt_object_read(l->bytes,l->size,&objs[0],&e)&&nt_object_read(r->bytes,r->size,&objs[1],&e);if(ok)ok=nt_object_link(objs,2,&linked,&e);int accepted=ok&&linked.sections[0].size==t&&linked.sections[1].size==r1&&linked.sections[2].size==d;Run x=run(i,l,l->size,r,r->size,8);cases++;checks++;if(accepted!=want_accept){failures++;fprintf(stderr,"FAIL boundary %s C oracle accepted=%d want=%d totals=%zu,%zu,%zu error=%s\n",n,accepted,want_accept,linked.sections[0].size,linked.sections[1].size,linked.sections[2].size,e.message);}if(((x.returned==821)?1:0)==want_accept||x.runtime||x.out[0]!=guard){failures++;fprintf(stderr,"FAIL boundary %s ret=%llu runtime=%llu cap_fired=%d want_fired=%d\n",n,(unsigned long long)x.returned,(unsigned long long)x.runtime,x.returned==821,!want_accept);}fprintf(stderr,"BOUNDARY %-22s sum=%zu C=%s cap_fired_nova=%d\n",n,want_sum,accepted?"accept":"refuse",x.returned==821);nt_object_free(&linked);for(size_t k=0;k<2;k++)nt_object_free(&objs[k]);free(objs);}
/* ---- A10: the merged byte layout, frozen and confronted ----
 *
 * A golden here pins the bytes, not a count. Each case freezes the merged
 * file size, the three section sizes, the three section file offsets, the
 * symbol and relocation tables, the entry symbol and the entry RVA the C PE
 * layout rule derives from them, plus an FNV-1a digest of the whole image so
 * that any byte that moves at all is caught. A moved count is not a failure
 * here: an unchanged count with a changed digest is exactly the regression
 * these exist to catch, and the digest is what reports it.
 *
 * The frozen values are not hand-copied from the Nova side. Every case is
 * built by the C oracle (nt_object_write), linked by the C oracle
 * (nt_object_link) and written by the C oracle, and the Nova merge is
 * required to match that byte for byte before its own golden is consulted.
 * A golden therefore cannot launder an oracle disagreement: if the C side
 * moves, byte parity fails; if only the Nova side moves, byte parity fails
 * too. The digest is the second, independent witness.
 *
 * A golden pins what is, not what should be. If a later wave proves one of
 * these layouts wrong, the golden is what must be re-derived and the change
 * justified in the commit that makes it, not silently re-recorded.
 */
typedef struct{const char*name;const char*contract;uint32_t section,flags;uint64_t offset,size;} GSym;
typedef struct{uint32_t section,kind,target;uint64_t offset;int64_t addend;} GRel;
typedef struct{size_t t,r,d;GSym sym[6];unsigned ns;GRel rel[6];unsigned nr;uint32_t entry;} GUnit;
typedef struct{const char*tag;uint64_t fnv;size_t size,ts,rs,ds,toff,roff,doff;uint32_t entry;uint64_t rva;
               GSym sym[6];unsigned ns;GRel rel[6];unsigned nr;} Golden;
/* The seven cases between them cover: the align16 gap in .text, a left unit
 * that is empty in all three sections, three sections whose bases are rounded
 * independently, relocation placement with the entry in the right unit, an
 * entry that exists only in the right unit, a name spelling long enough to
 * move the string table, and a left unit whose own file offsets are nowhere
 * near its merged offsets so a copy instead of a recompute would be visible.
 * The last one is the machine-checkable form of the hand-copied-offset defect
 * this criterion is about: input_offsets 688/240 against merged toff 688 is
 * only correct because the offset is recomputed from the merged sizes.
 */
static const GUnit G1L={.t=17},G1R={.t=1};
static const GUnit G2L={.t=0,.r=0,.d=0},G2R={.t=3,.r=1,.d=2};
static const GUnit G3L={.t=1,.r=9,.d=17},G3R={.t=2,.r=3,.d=4};
static const GUnit G4L={.t=16,.sym={{"alpha","fn:u64",1,NT_OBJECT_FUNCTION|NT_OBJECT_EXPORT,0,16}},.ns=1,
                        .rel={{1,NT_OBJECT_REL32,1,0,-4}},.nr=1};
static const GUnit G4R={.t=16,.sym={{"beta","fn:u64",1,NT_OBJECT_FUNCTION|NT_OBJECT_EXPORT,0,16}},.ns=1,
                        .rel={{1,NT_OBJECT_DIR64,1,8,5}},.nr=1,.entry=1};
static const GUnit G5L={.t=4};
static const GUnit G5R={.t=4,.sym={{"alpha","fn:u64",1,NT_OBJECT_FUNCTION|NT_OBJECT_EXPORT,0,4}},.ns=1,.entry=1};
static const GUnit G6L={.t=8,.r=8,.d=8,.sym={{"mm","data:u8",2,NT_OBJECT_VARIABLE|NT_OBJECT_EXPORT,0,8}},.ns=1};
static const GUnit G6R={.t=8,.r=8,.d=8,
                        .sym={{"averyveryverylongname","data:u64",2,NT_OBJECT_VARIABLE|NT_OBJECT_EXPORT,0,8}},.ns=1};
static const GUnit G7L={.t=8,.r=8,.d=8,
                        .sym={{"aaa","fn:u64",1,NT_OBJECT_FUNCTION|NT_OBJECT_EXPORT,0,8},
                              {"bbb","fn:u64",1,NT_OBJECT_FUNCTION|NT_OBJECT_EXPORT,0,8},
                              {"ccc","data:u8",2,NT_OBJECT_VARIABLE|NT_OBJECT_EXPORT,0,8},
                              {"ddd","data:u8",2,NT_OBJECT_VARIABLE|NT_OBJECT_EXPORT,0,8},
                              {"eee","data:u8",3,NT_OBJECT_VARIABLE|NT_OBJECT_EXPORT,0,8},
                              {"fff","data:u8",3,NT_OBJECT_VARIABLE|NT_OBJECT_EXPORT,0,8}},
                        .ns=6,.entry=1};
static const GUnit G7R={.t=0,.r=0,.d=0};
static const Golden GOLDEN[]={
 {.tag="text_align16_padding",.fnv=0xa446cf719daddef0ULL,.size=288,.ts=33,.rs=0,.ds=0,
  .toff=240,.roff=288,.doff=288,.entry=0,.rva=0},
 {.tag="all_sections_from_right",.fnv=0x8de2031c34edc4eeULL,.size=274,.ts=3,.rs=1,.ds=2,
  .toff=240,.roff=256,.doff=272,.entry=0,.rva=0},
 {.tag="independent_section_bases",.fnv=0x5188fc84d652d398ULL,.size=340,.ts=18,.rs=19,.ds=36,
  .toff=240,.roff=272,.doff=304,.entry=0,.rva=0},
 {.tag="reloc_placement_and_entry",.fnv=0x8bbd352a1e18f6bbULL,.size=512,.ts=32,.rs=0,.ds=0,
  .toff=480,.roff=512,.doff=512,.entry=2,.rva=4112,
  .sym={{"alpha",0,1,0,0,16},{"beta",0,1,0,16,16}},.ns=2,
  .rel={{1,1,1,0,-4},{1,2,2,24,5}},.nr=2},
 {.tag="entry_from_right_only",.fnv=0x676f3d4bcf922832ULL,.size=352,.ts=20,.rs=0,.ds=0,
  .toff=320,.roff=352,.doff=352,.entry=1,.rva=4112,
  .sym={{"alpha",0,1,0,16,4}},.ns=1},
 {.tag="name_spelling_string_table",.fnv=0x888634d0601ae910ULL,.size=504,.ts=24,.rs=24,.ds=24,
  .toff=416,.roff=448,.doff=480,.entry=0,.rva=0,
  .sym={{"averyveryverylongname",0,2,0,16,8},{"mm",0,2,0,0,8}},.ns=2},
 {.tag="offsets_recomputed_not_copied",.fnv=0x0016a79032c0e0f0ULL,.size=736,.ts=16,.rs=16,.ds=16,
  .toff=688,.roff=704,.doff=720,.entry=1,.rva=4096,
  .sym={{"aaa",0,1,0,0,8},{"bbb",0,1,0,0,8},{"ccc",0,2,0,0,8},
        {"ddd",0,2,0,0,8},{"eee",0,3,0,0,8},{"fff",0,3,0,0,8}},.ns=6},
};
static const size_t GOLDEN_N=sizeof GOLDEN/sizeof GOLDEN[0];
static uint64_t fnv1a(const uint8_t*p,size_t n){uint64_t h=1469598103934665603ULL;
  for(size_t i=0;i<n;i++){h^=p[i];h*=1099511628211ULL;}return h;}
/* Builds one link unit through the C oracle so both sides of the comparison
 * are produced by the same writer and only the merge differs. */
static NtBuffer gunit(const GUnit*u){NtObject o={0};o.target=1;o.entry_symbol=u->entry;
  uint8_t*raw[3]={0};size_t want[3]={u->t,u->r,u->d};
  for(unsigned k=0;k<3;k++)if(want[k]){raw[k]=malloc(want[k]);
    if(!raw[k]){CHECK(0,"golden payload allocation");return(NtBuffer){0};}
    memset(raw[k],(int)(0x40+0x11*k),want[k]);o.sections[k]=(NtBuffer){raw[k],want[k],want[k]};}
  NtObjectSymbol syms[6];for(unsigned k=0;k<u->ns;k++)
    syms[k]=(NtObjectSymbol){(char*)u->sym[k].name,(char*)u->sym[k].contract,u->sym[k].section,
                             u->sym[k].flags,u->sym[k].offset,u->sym[k].size};
  NtObjectReloc rels[6];for(unsigned k=0;k<u->nr;k++)
    rels[k]=(NtObjectReloc){u->rel[k].section,u->rel[k].kind,u->rel[k].target,u->rel[k].offset,u->rel[k].addend};
  if(u->ns){o.symbols=syms;o.symbol_count=u->ns;}
  if(u->nr){o.relocations=rels;o.relocation_count=u->nr;}
  NtBuffer file={0};NtDiagnostic e={0};
  CHECK(nt_object_write(&o,&file,&e),"oracle writes golden unit");
  if(!file.bytes)fprintf(stderr,"E golden unit %s\n",e.message);
  for(unsigned k=0;k<3;k++)free(raw[k]);
  return file;}
/* One golden case end to end: run the merge, pin every observable field, and
 * confront the C oracle. `out` receives 8+size bytes, the size prefix first. */
static void golden_case(const NovaHostImage*i,const Golden*g,const GUnit*ul,const GUnit*ur){
  NtBuffer l=gunit(ul),r=gunit(ur);
  if(!l.bytes||!r.bytes){free(l.bytes);free(r.bytes);return;}
  Run x=run(i,&l,l.size,&r,r.size,sizeof x.out);cases++;
  checks++;
  if(x.returned!=0||x.runtime){failures++;
    fprintf(stderr,"FAIL golden %s merge ret=%llu runtime=%llu\n",g->tag,
            (unsigned long long)x.returned,(unsigned long long)x.runtime);
    free(l.bytes);free(r.bytes);return;}
  const uint8_t*a=x.out;
  size_t n=(size_t)r64(a);
  /* The frozen layout. Each field is checked on its own so a failure says
   * which one moved instead of only that a digest differs. */
  NtObject m={0};NtDiagnostic e={0};
  int readable=n>0&&n+8<=sizeof x.out&&nt_object_read(a+8,n,&m,&e);
  checks++;
  if(!readable){failures++;fprintf(stderr,"FAIL golden %s merged NXO unreadable: %s\n",g->tag,e.message);
    free(l.bytes);free(r.bytes);return;}
  NtPeLayout pl;int have=nt_pe_layout(m.sections[0].size,m.sections[1].size,m.sections[2].size,&pl);
  uint64_t rva=0;
  if(have&&m.entry_symbol)rva=nt_pe_logical_rva(&pl,m.symbols[m.entry_symbol-1].section)
                              +m.symbols[m.entry_symbol-1].offset;
  struct{const char*field;uint64_t got,want;}F[]={
    {"size",n,g->size},{"text size",m.sections[0].size,g->ts},{"rdata size",m.sections[1].size,g->rs},
    {"data size",m.sections[2].size,g->ds},
    {"text offset",r64(a+8+96+24),g->toff},{"rdata offset",r64(a+8+96+48+24),g->roff},
    {"data offset",r64(a+8+96+96+24),g->doff},
    {"entry",m.entry_symbol,g->entry},{"entry rva",rva,g->rva},
    {"symbol count",m.symbol_count,g->ns},{"relocation count",m.relocation_count,g->nr},
    {"digest",fnv1a(a+8,n),g->fnv}};
  for(unsigned k=0;k<sizeof F/sizeof F[0];k++){checks++;
    if(F[k].got!=F[k].want){failures++;
      fprintf(stderr,"FAIL golden %s %s got=%llu want=%llu\n",g->tag,F[k].field,
              (unsigned long long)F[k].got,(unsigned long long)F[k].want);}}
  for(unsigned k=0;k<g->ns;k++){checks++;
    if(strcmp(m.symbols[k].name,g->sym[k].name)||m.symbols[k].section!=g->sym[k].section||
       m.symbols[k].offset!=g->sym[k].offset||m.symbols[k].size!=g->sym[k].size){failures++;
      fprintf(stderr,"FAIL golden %s symbol %u got=%s/s%u/@%llu want=%s/s%u/@%llu\n",g->tag,k,
              m.symbols[k].name,m.symbols[k].section,(unsigned long long)m.symbols[k].offset,
              g->sym[k].name,g->sym[k].section,(unsigned long long)g->sym[k].offset);}}
  for(unsigned k=0;k<g->nr;k++){checks++;
    if(m.relocations[k].section!=g->rel[k].section||m.relocations[k].kind!=g->rel[k].kind||
       m.relocations[k].offset!=g->rel[k].offset||m.relocations[k].target!=g->rel[k].target||
       m.relocations[k].addend!=g->rel[k].addend){failures++;
      fprintf(stderr,"FAIL golden %s reloc %u got=s%u/k%u/@%llu->%u want=s%u/k%u/@%llu->%u\n",g->tag,k,
              m.relocations[k].section,m.relocations[k].kind,(unsigned long long)m.relocations[k].offset,
              m.relocations[k].target,g->rel[k].section,g->rel[k].kind,
              (unsigned long long)g->rel[k].offset,g->rel[k].target);}}
  /* Every alignment pad inside the merged image is part of the layout and
   * must be zero, which is what a byte copied from an unwritten allocation
   * would break. */
  for(unsigned k=1;k<3;k++){uint64_t from=r64(a+8+96+(k-1)*48+24)+r64(a+8+96+(k-1)*48+16),to=r64(a+8+96+k*48+24);
    for(uint64_t q=from;q<to;q++){checks++;if(a[8+q]!=0){failures++;
      fprintf(stderr,"FAIL golden %s pad byte %llu is %u\n",g->tag,(unsigned long long)q,a[8+q]);break;}}}
  /* The C oracle links and writes the very same two units. */
  NtObject ins[2]={{0}},linked={0};NtBuffer oracle={0};
  if(nt_object_read(l.bytes,l.size,&ins[0],&e)&&nt_object_read(r.bytes,r.size,&ins[1],&e)&&
     nt_object_link(ins,2,&linked,&e)&&nt_object_write(&linked,&oracle,&e)){checks++;
    if(n!=oracle.size||memcmp(a+8,oracle.bytes,n)){failures++;
      fprintf(stderr,"FAIL golden %s diverges from the C oracle (%zu vs %zu)\n",g->tag,n,oracle.size);}}
  else{checks++;failures++;fprintf(stderr,"FAIL golden %s C oracle: %s\n",g->tag,e.message);}
  /* Determinism: the same inputs again in the same process must not move a
   * byte. This is the check a seeded non-determinism has to go red on. */
  Run y=run(i,&l,l.size,&r,r.size,sizeof y.out);checks++;
  if(y.returned!=0||memcmp(a,y.out,n+8)){failures++;size_t at=0;while(at<n+8&&a[at]==y.out[at])at++;
    fprintf(stderr,"FAIL golden %s not reproducible, first difference at %zu\n",g->tag,at);}
  /* The same two units presented from different host addresses. A merged
   * image that carried a pointer, an allocator address or anything else
   * derived from where its inputs happened to live would move here, and the
   * second image in main is mapped at a different address again, so the two
   * checks together cover the image address as well as the input address. */
  {
    static uint8_t*sl=NULL,*sr=NULL;
    const size_t skew=4093;
    sl=malloc(l.size+skew);sr=malloc(r.size+skew);
    CHECK(sl&&sr,"skewed input allocation");
    if(sl&&sr){memcpy(sl+skew,l.bytes,l.size);memcpy(sr+skew,r.bytes,r.size);
      NtBuffer lv={sl+skew,l.size,l.size},rv={sr+skew,r.size,r.size};
      Run z=run(i,&lv,lv.size,&rv,rv.size,sizeof z.out);checks++;
      if(z.returned!=0||memcmp(a,z.out,n+8)){failures++;size_t at=0;
        while(at<n+8&&a[at]==z.out[at])at++;
        fprintf(stderr,"FAIL golden %s output depends on the input address, differs at %zu\n",g->tag,at);}}
    free(sl);free(sr);
  }
  nt_object_free(&m);nt_object_free(&linked);nt_object_free(&ins[0]);nt_object_free(&ins[1]);
  free(oracle.bytes);free(l.bytes);free(r.bytes);}
int main(void){const char*paths[]={"tests/nova/tests/nxo-merge-entry.nova","compiler/nova/formats/nxo/nxo_merge.nova","compiler/nova/formats/nxo/nxo.nova","compiler/nova/formats/pe/pe.nova"};char*sources[4]={0};NtFInput inputs[4];for(unsigned i=0;i<4;i++){size_t n=0;sources[i]=load(paths[i],&n);inputs[i]=(NtFInput){paths[i],sources[i],n};}CHECK(sources[0]&&sources[1]&&sources[2]&&sources[3],"sources load");NtArtifact a={0};int compiled=sources[0]&&sources[1]&&sources[2]&&sources[3]&&nova_compile_many_v2(inputs,4,&a);CHECK(compiled,"modules compile");if(!compiled)fprintf(stderr,"E%u %zu:%zu %s\n",a.error.code,a.error.line,a.error.column,a.error.message);NovaHostImage image={0};CHECK(compiled&&nova_host_map(&a,&image),"image maps");
 if(image.memory){const uint8_t lt[]={1,2},lr[]={3},rt[]={4},rd[]={5,6};NtBuffer left=make_object(1,lt,2,lr,1,NULL,0,0),right=make_object(1,rt,1,NULL,0,rd,2,0),other=make_object(2,rt,1,NULL,0,NULL,0,0),with_symbol=make_object(1,rt,1,NULL,0,NULL,0,1);
  Run x=run(&image,&left,left.size,&right,right.size,sizeof(x.out));cases++;CHECK(x.returned==0&&x.runtime==0,"merge success");uint64_t size=r64(x.out);NtObject merged={0};NtDiagnostic e={0};CHECK(size>0&&size+8<=sizeof(x.out)&&nt_object_read(x.out+8,size,&merged,&e),"merged NXO reads");if(merged._owned){CHECK(merged.target==1&&merged.entry_symbol==0&&merged.symbol_count==0&&merged.relocation_count==0,"merged metadata");CHECK(merged.sections[0].size==17&&merged.sections[0].bytes[0]==1&&merged.sections[0].bytes[1]==2&&merged.sections[0].bytes[16]==4,"merged text");int rdata_padding=1;for(size_t pad=1;pad<merged.sections[1].size;pad++)if(merged.sections[1].bytes[pad]!=0)rdata_padding=0;CHECK(merged.sections[1].size==16&&merged.sections[1].bytes[0]==3&&rdata_padding,"merged rdata and empty-right padding");CHECK(merged.sections[2].size==2&&merged.sections[2].bytes[0]==5&&merged.sections[2].bytes[1]==6,"merged data");nt_object_free(&merged);}
  NtObject oracle_inputs[2]={{0}},oracle_linked={0};NtBuffer oracle_file={0};CHECK(nt_object_read(left.bytes,left.size,&oracle_inputs[0],&e)&&nt_object_read(right.bytes,right.size,&oracle_inputs[1],&e),"oracle inputs read");CHECK(nt_object_link(oracle_inputs,2,&oracle_linked,&e),"C oracle links");CHECK(nt_object_write(&oracle_linked,&oracle_file,&e),"C oracle writes merge");CHECK(size==oracle_file.size&&!memcmp(x.out+8,oracle_file.bytes,oracle_file.size),"Nova merge byte parity");free(oracle_file.bytes);nt_object_free(&oracle_linked);nt_object_free(&oracle_inputs[0]);nt_object_free(&oracle_inputs[1]);
  Run y=run(&image,&left,left.size,&right,right.size,sizeof(y.out));cases++;CHECK(y.returned==0&&!memcmp(x.out,y.out,(size_t)size+8),"merge deterministic");
  expect_error(&image,"target mismatch",&left,left.size,&other,other.size,sizeof(x.out),820);
  Run entry=run(&image,&left,left.size,&with_symbol,with_symbol.size,sizeof(entry.out));cases++;
  CHECK(entry.returned==0&&entry.runtime==0,"right entry accepted");
  uint64_t entry_size=r64(entry.out);NtObject entry_object={0};NtDiagnostic entry_error={0};
  CHECK(entry_size>0&&nt_object_read(entry.out+8,entry_size,&entry_object,&entry_error),"entry NXO reads");
  if(entry_object._owned){CHECK(entry_object.entry_symbol==1&&entry_object.symbol_count==1&&entry_object.symbols[0].offset==16,"right entry remapped");nt_object_free(&entry_object);}
  expect_error(&image,"two entries",&with_symbol,with_symbol.size,&with_symbol,with_symbol.size,sizeof(x.out),826);
  expect_error(&image,"short output",&left,left.size,&right,right.size,8,822);expect_error(&image,"truncated",&left,left.size-1,&right,right.size,sizeof(x.out),800);
  const uint8_t left_data[]={7,8};
  NtObjectSymbol left_symbol={"b","fn:u64",1,NT_OBJECT_FUNCTION,0,1};
  NtObjectSymbol right_symbol={"a","data:u8",3,NT_OBJECT_VARIABLE,1,1};
  NtObject left_object={0},right_object={0};left_object.target=right_object.target=1;
  left_object.sections[0]=(NtBuffer){(uint8_t*)lt,2,2};left_object.sections[2]=(NtBuffer){(uint8_t*)left_data,2,2};
  right_object.sections[2]=(NtBuffer){(uint8_t*)rd,2,2};
  left_object.symbols=&left_symbol;left_object.symbol_count=1;
  right_object.symbols=&right_symbol;right_object.symbol_count=1;
  NtBuffer left_symbols={0},right_symbols={0};NtDiagnostic symbol_error={0};
  CHECK(nt_object_write(&left_object,&left_symbols,&symbol_error),"oracle writes left symbols");
  CHECK(nt_object_write(&right_object,&right_symbols,&symbol_error),"oracle writes right symbols");
  Run z=run(&image,&left_symbols,left_symbols.size,&right_symbols,right_symbols.size,sizeof(z.out));cases++;
  CHECK(z.returned==0&&z.runtime==0,"symbol merge success");
  uint64_t symbol_size=r64(z.out);NtObject symbol_merged={0};
  CHECK(symbol_size>0&&nt_object_read(z.out+8,symbol_size,&symbol_merged,&symbol_error),"symbol merge reads");
  if(symbol_merged._owned){CHECK(symbol_merged.symbol_count==2&&!strcmp(symbol_merged.symbols[0].name,"a")&&!strcmp(symbol_merged.symbols[1].name,"b"),"symbols globally sorted");CHECK(symbol_merged.symbols[0].offset==17&&symbol_merged.symbols[1].offset==0,"right symbol offset adjusted");nt_object_free(&symbol_merged);}
  NtObjectSymbol duplicate_symbol={"b","data:u8",3,NT_OBJECT_VARIABLE,0,1};
  right_object.symbols=&duplicate_symbol;NtBuffer duplicate_file={0};
  CHECK(nt_object_write(&right_object,&duplicate_file,&symbol_error),"oracle writes duplicate symbol");
  expect_error(&image,"duplicate symbol",&left_symbols,left_symbols.size,&duplicate_file,duplicate_file.size,sizeof(x.out),823);
  NtObjectSymbol import_symbol={"external","fn:u64",0,NT_OBJECT_FUNCTION|NT_OBJECT_IMPORT,0,0};
  right_object.symbols=&import_symbol;right_object.sections[2]=(NtBuffer){0};NtBuffer import_file={0};
  CHECK(nt_object_write(&right_object,&import_file,&symbol_error),"oracle writes import symbol");
  expect_error(&image,"unresolved import",&left_symbols,left_symbols.size,&import_file,import_file.size,sizeof(x.out),824);
  free(left_symbols.bytes);free(right_symbols.bytes);free(duplicate_file.bytes);free(import_file.bytes);
  const uint8_t reloc_text[8]={0};
  NtObjectSymbol left_reloc_symbol={"z","fn:u64",1,NT_OBJECT_FUNCTION,0,8};
  NtObjectSymbol right_reloc_symbol={"y","fn:u64",1,NT_OBJECT_FUNCTION,0,8};
  NtObjectReloc left_reloc={1,NT_OBJECT_REL32,1,0,-4};
  NtObjectReloc right_reloc={1,NT_OBJECT_DIR64,1,0,5};
  NtObject left_reloc_object={0},right_reloc_object={0};
  left_reloc_object.target=right_reloc_object.target=1;
  left_reloc_object.sections[0]=(NtBuffer){(uint8_t*)reloc_text,8,8};
  right_reloc_object.sections[0]=(NtBuffer){(uint8_t*)reloc_text,8,8};
  left_reloc_object.symbols=&left_reloc_symbol;left_reloc_object.symbol_count=1;
  right_reloc_object.symbols=&right_reloc_symbol;right_reloc_object.symbol_count=1;
  left_reloc_object.relocations=&left_reloc;left_reloc_object.relocation_count=1;
  right_reloc_object.relocations=&right_reloc;right_reloc_object.relocation_count=1;
  NtBuffer left_reloc_file={0},right_reloc_file={0};NtDiagnostic reloc_error={0};
  CHECK(nt_object_write(&left_reloc_object,&left_reloc_file,&reloc_error),"oracle writes left relocation");
  CHECK(nt_object_write(&right_reloc_object,&right_reloc_file,&reloc_error),"oracle writes right relocation");
  Run rel=run(&image,&left_reloc_file,left_reloc_file.size,&right_reloc_file,right_reloc_file.size,sizeof(rel.out));cases++;
  CHECK(rel.returned==0&&rel.runtime==0,"relocation merge success");
  uint64_t reloc_size=r64(rel.out);NtObject reloc_merged={0};
  CHECK(reloc_size>0&&nt_object_read(rel.out+8,reloc_size,&reloc_merged,&reloc_error),"relocation merge reads");
  if(reloc_merged._owned){CHECK(reloc_merged.symbol_count==2&&!strcmp(reloc_merged.symbols[0].name,"y")&&!strcmp(reloc_merged.symbols[1].name,"z"),"relocation symbols remapped order");CHECK(reloc_merged.relocation_count==2&&reloc_merged.relocations[0].offset==0&&reloc_merged.relocations[0].target==2&&reloc_merged.relocations[0].kind==NT_OBJECT_REL32&&reloc_merged.relocations[0].addend==-4,"left relocation remapped");CHECK(reloc_merged.relocations[1].offset==16&&reloc_merged.relocations[1].target==1&&reloc_merged.relocations[1].kind==NT_OBJECT_DIR64&&reloc_merged.relocations[1].addend==5,"right relocation shifted");nt_object_free(&reloc_merged);}
  free(left_reloc_file.bytes);free(right_reloc_file.bytes);
  NtObjectSymbol imported={"target","fn:u64",0,NT_OBJECT_FUNCTION|NT_OBJECT_IMPORT,0,0};
  NtObjectSymbol exported={"target","fn:u64",1,NT_OBJECT_FUNCTION|NT_OBJECT_EXPORT,0,8};
  NtObjectReloc import_reloc={1,NT_OBJECT_REL32,1,0,0};
  NtObject importer={0},provider={0};importer.target=provider.target=1;
  importer.sections[0]=(NtBuffer){(uint8_t*)reloc_text,8,8};provider.sections[0]=(NtBuffer){(uint8_t*)reloc_text,8,8};
  importer.symbols=&imported;importer.symbol_count=1;importer.relocations=&import_reloc;importer.relocation_count=1;
  provider.symbols=&exported;provider.symbol_count=1;
  NtBuffer importer_file={0},provider_file={0};NtDiagnostic import_error={0};
  CHECK(nt_object_write(&importer,&importer_file,&import_error),"oracle writes importer");
  CHECK(nt_object_write(&provider,&provider_file,&import_error),"oracle writes provider");
  Run linked=run(&image,&importer_file,importer_file.size,&provider_file,provider_file.size,sizeof(linked.out));cases++;
  CHECK(linked.returned==0&&linked.runtime==0,"import resolves");
  uint64_t linked_size=r64(linked.out);NtObject linked_object={0};
  CHECK(linked_size>0&&nt_object_read(linked.out+8,linked_size,&linked_object,&import_error),"resolved NXO reads");
  if(linked_object._owned){CHECK(linked_object.symbol_count==1&&!strcmp(linked_object.symbols[0].name,"target")&&(linked_object.symbols[0].flags&NT_OBJECT_IMPORT)==0&&linked_object.symbols[0].offset==16,"definition kept and shifted");CHECK(linked_object.relocation_count==1&&linked_object.relocations[0].target==1&&linked_object.relocations[0].offset==0,"import relocation resolved");nt_object_free(&linked_object);}
  NtObjectSymbol private_definition={"target","fn:u64",1,NT_OBJECT_FUNCTION,0,8};provider.symbols=&private_definition;NtBuffer private_file={0};
  CHECK(nt_object_write(&provider,&private_file,&import_error),"oracle writes private provider");
  expect_error(&image,"definition not exported",&importer_file,importer_file.size,&private_file,private_file.size,sizeof(x.out),824);
  NtObjectSymbol wrong_contract={"target","fn:u32",1,NT_OBJECT_FUNCTION|NT_OBJECT_EXPORT,0,8};provider.symbols=&wrong_contract;NtBuffer contract_file={0};
  CHECK(nt_object_write(&provider,&contract_file,&import_error),"oracle writes wrong contract");
  expect_error(&image,"contract mismatch",&importer_file,importer_file.size,&contract_file,contract_file.size,sizeof(x.out),825);
  NtObjectSymbol wrong_role={"target","data:u64",3,NT_OBJECT_VARIABLE|NT_OBJECT_EXPORT,0,8};provider.symbols=&wrong_role;provider.sections[0]=(NtBuffer){0};provider.sections[2]=(NtBuffer){(uint8_t*)reloc_text,8,8};NtBuffer role_file={0};
  CHECK(nt_object_write(&provider,&role_file,&import_error),"oracle writes wrong role");
  expect_error(&image,"role mismatch",&importer_file,importer_file.size,&role_file,role_file.size,sizeof(x.out),825);
  free(importer_file.bytes);free(provider_file.bytes);free(private_file.bytes);free(contract_file.bytes);free(role_file.bytes);
   for(unsigned k=0;k<sizeof SHAPES/sizeof SHAPES[0];k++)probe_shape(&image,&SHAPES[k]);
   /* aggregate payload cap, exactly 64MiB: object_link.c:86 compares the three
    * totals with a strict >, so 67108864 is accepted. The left unit holds
    * 64MiB-240 bytes of text, the largest an NXO can carry because the header
    * and the section table cost 240 bytes, and the right unit adds the 240
    * bytes that reach the cap exactly. */
   {
     const size_t LIMIT=67108864;size_t lt=LIMIT-240;uint8_t*payload=calloc(lt,1);
     CHECK(payload!=NULL,"boundary payload allocation");
     if(payload){memset(payload,0x5a,lt);NtBuffer big_left=plain_object(lt,payload,0,NULL,0,NULL),big_right=plain_object(240,payload,0,NULL,0,NULL);free(payload);boundary_case(&image,"sum exactly 64MiB",&big_left,&big_right,1,LIMIT,0,0,LIMIT);free(big_left.bytes);free(big_right.bytes);}
   }
   /* aggregate payload cap, 64MiB+1: three sections that are each legal on
    * their own and whose sum is one byte over the cap. */
   {
     const size_t T=33554432,R=22369632,D=11184801;uint8_t*payload=calloc(T+R+D,1);
     CHECK(payload!=NULL,"over payload allocation");
     if(payload){memset(payload,0x6b,T+R+D);NtBuffer big_left=plain_object(T,payload,0,NULL,0,NULL),big_right=plain_object(0,NULL,R,payload+R,D,payload+R+D);free(payload);boundary_case(&image,"sum 64MiB plus one",&big_left,&big_right,0,T,R,D,T+R+D);free(big_left.bytes);free(big_right.bytes);}
   }
  /* A10: the merged byte layout, frozen. Each case pins the observable
   * fields and the whole-image digest, is confronted with the C oracle, and
   * is required to reproduce byte for byte on a second run. */
  {
    static const GUnit*const UL[7]={&G1L,&G2L,&G3L,&G4L,&G5L,&G6L,&G7L};
    static const GUnit*const UR[7]={&G1R,&G2R,&G3R,&G4R,&G5R,&G6R,&G7R};
    for(unsigned k=0;k<GOLDEN_N;k++)golden_case(&image,&GOLDEN[k],UL[k],UR[k]);
    /* The module is recompiled and the modules are presented in the other
     * order the language makes equivalent. Same source, same answer: a
     * rebuild that moved a byte, or a compile that depended on the order the
     * sources were handed over, would show up here and nowhere else. The
     * reversed order keeps the entry module reachable, since the Nova ABI
     * picks the single `main` across all modules. */
    char*rs[4]={0};NtFInput ri[4];const char*rp[4]={paths[2],paths[3],paths[1],paths[0]};
    for(unsigned k=0;k<4;k++){size_t n=0;rs[k]=load(rp[k],&n);ri[k]=(NtFInput){rp[k],rs[k],n};}
    NtArtifact ra={0};int rc=rs[0]&&rs[1]&&rs[2]&&rs[3]&&nova_compile_many_v2(ri,4,&ra);
    CHECK(rc,"modules compile in reversed order");
    if(!rc)fprintf(stderr,"E reversed %u %zu:%zu %s\n",ra.error.code,ra.error.line,ra.error.column,ra.error.message);
    NovaHostImage ri_image={0};CHECK(rc&&nova_host_map(&ra,&ri_image),"reversed image maps");
    if(ri_image.memory){
      for(unsigned k=0;k<GOLDEN_N;k++){
        NtBuffer l=gunit(UL[k]),r=gunit(UR[k]);
        if(!l.bytes||!r.bytes){free(l.bytes);free(r.bytes);continue;}
        Run x=run(&image,&l,l.size,&r,r.size,sizeof x.out);
        Run y=run(&ri_image,&l,l.size,&r,r.size,sizeof y.out);
        cases++;checks++;
        size_t n=x.returned==0?(size_t)r64(x.out):0;
        if(x.returned!=0||y.returned!=0||n==0||memcmp(x.out,y.out,n+8)){failures++;
          size_t at=0;while(at<n+8&&x.out[at]==y.out[at])at++;
          fprintf(stderr,"FAIL rebuild %s recompiled or reordered image moved a byte at %zu (ret %llu/%llu)\n",
                  GOLDEN[k].tag,at,(unsigned long long)x.returned,(unsigned long long)y.returned);}
        free(l.bytes);free(r.bytes);}
      nova_host_unmap(&ri_image);}
    if(rc)nt_artifact_free(&ra);
    for(unsigned k=0;k<4;k++)free(rs[k]);
  }
   free(left.bytes);free(right.bytes);free(other.bytes);free(with_symbol.bytes);}
 if(image.memory) nova_host_unmap(&image);
 if(compiled) nt_artifact_free(&a);
 for(unsigned i=0;i<4;i++) free(sources[i]);
 printf("NTASM_NOVA_NXO_MERGE checks=%u failures=%u cases=%u\n",checks,failures,cases);
 return failures?1:0;
}
