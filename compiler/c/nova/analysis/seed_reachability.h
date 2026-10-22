#ifndef NG_NOVA_SEED_REACHABILITY_H
#define NG_NOVA_SEED_REACHABILITY_H
/* C_SEED_ORACLE link compaction, not a binary disassembler. Input must be the
 * verified NtCodeImage emitted by codegen: every direct call/RIP reference
 * already has typed relocation metadata. Never infer references from bytes.
 * Internal branch bytes move with their whole function. Data is retained.
 */
#include "../frontend/nova.h"
#include "../../ntasm/backend/codegen.h"
#include "../../ntasm/formats/pe_layout.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  size_t symbol, old_offset, size, new_offset, first_edge;
  unsigned roots, live;
} NvsFunction;
typedef struct { NtFId id; size_t index; } NvsId;
typedef struct { size_t owner, function, variable, next; unsigned width; } NvsRef;
typedef struct { uint32_t section; size_t offset, width; } NvsSite;
static int nvs_error(NtCodeDiagnostic *d,unsigned code,const char *message){
  if(d){memset(d,0,sizeof *d);d->code=code;snprintf(d->message,sizeof d->message,"%s",message);}return 0;
}
static int nvs_fn_order(const void *a,const void *b){
  const NvsFunction *x=a,*y=b;return x->old_offset<y->old_offset?-1:x->old_offset>y->old_offset;
}
static int nvs_id_order(const void *a,const void *b){
  const NvsId *x=a,*y=b;return x->id<y->id?-1:x->id>y->id;
}
static int nvs_site_order(const void *a,const void *b){
  const NvsSite *x=a,*y=b;
  if(x->section!=y->section)return x->section<y->section?-1:1;
  return x->offset<y->offset?-1:x->offset>y->offset;
}
static size_t nvs_lookup(const NvsId *map,size_t n,NtFId id){
  size_t a=0,z=n;
  while(a<z){size_t m=a+(z-a)/2;if(map[m].id<id)a=m+1;else z=m;}
  return a<n&&map[a].id==id?map[a].index:SIZE_MAX;
}
static size_t nvs_owner(const NvsFunction *f,size_t n,size_t offset,size_t width){
  size_t a=0,z=n;
  while(a<z){size_t m=a+(z-a)/2;if(f[m].old_offset<=offset)a=m+1;else z=m;}
  if(!a)return SIZE_MAX;
  --a;
  size_t delta=offset-f[a].old_offset;
  return delta<=f[a].size&&width<=f[a].size-delta?a:SIZE_MAX;
}
static uint64_t nvs_read(const uint8_t *p,unsigned width){
  uint64_t v=0;for(unsigned i=0;i<width;i++)v|=(uint64_t)p[i]<<(i*8);return v;
}
static void nvs_store(uint8_t *p,unsigned width,uint64_t value){
  for(unsigned i=0;i<width;i++)p[i]=(uint8_t)(value>>(i*8));
}
/* Raw code-image coordinates, same layout codegen patches before PE headers:
 * text0, rdata at page(text)+8 (loader anchor), data at next page. */
static int nvs_bases(size_t text,size_t rdata,size_t data,uint64_t base[4]){
  if(!text||text>UINT32_MAX-4096u||rdata>UINT32_MAX-4096u||data>UINT32_MAX-4096u)return 0;
  uint64_t ro=((uint64_t)text+4095)&~UINT64_C(4095);
  uint64_t rw=(ro+8+rdata+4095)&~UINT64_C(4095);
  if(ro+8+rdata>UINT32_MAX||rw+data>UINT32_MAX)return 0;
  base[0]=0;base[1]=0;base[2]=ro+8;base[3]=rw;return 1;
}
static int nvs_add_offset(size_t value,int64_t addend,size_t limit,int one_past,uint64_t *out){
  if(value>INT64_MAX)return 0;
  int64_t x=(int64_t)value;
  if((addend>0&&x>INT64_MAX-addend)||(addend<0&&x<INT64_MIN-addend))return 0;
  x+=addend;
  if(x<0||(uint64_t)x>limit||(!one_past&&(uint64_t)x==limit))return 0;
  *out=(uint64_t)x;return 1;
}
static int nvs_rel32(uint64_t source,uint64_t target,uint64_t *bits){
  if(source>INT64_MAX-4||target>INT64_MAX)return 0;
  int64_t delta=(int64_t)target-(int64_t)(source+4);
  if(delta<INT32_MIN||delta>INT32_MAX)return 0;
  *bits=(uint32_t)(int32_t)delta;return 1;
}

static int nova_seed_compact_image(NtCodeImage *im,unsigned policy,
    NovaSeedReachabilityStats *stats,NtCodeDiagnostic *diagnostic){
  NovaSeedReachabilityStats result={0};result.root_policy=policy;
  if(stats)memset(stats,0,sizeof *stats);
  if(diagnostic)memset(diagnostic,0,sizeof *diagnostic);
  if(!im||!im->bytes||!im->size||im->size>im->capacity||im->entry>=im->size||
     !im->symbols||!im->symbol_count||im->symbol_count>im->symbol_capacity||
     im->relocation_count>im->relocation_capacity||
     (im->relocation_count&&!im->relocations)||
     im->rdata.size>im->rdata.capacity||im->data.size>im->data.capacity||
     (im->rdata.size&&!im->rdata.bytes)||(im->data.size&&!im->data.bytes))
    return nvs_error(diagnostic,NTCG_E_INTERNAL,"seed image metadata missing");
  if(policy!=NOVA_SEED_ALL_EXPORTS&&policy!=NOVA_SEED_ENTRY_ONLY_CLOSED_APPLICATION)
    return nvs_error(diagnostic,NTCG_E_UNSUPPORTED,"unknown seed root policy");
  if(im->symbol_count>1048576||im->relocation_count>16777216)
    return nvs_error(diagnostic,NTCG_E_RANGE,"seed metadata count exceeds bounded optimizer");
  size_t nf=0,nv=0,nr=im->relocation_count;
  for(size_t i=0;i<im->symbol_count;i++){
    const NtCodeSymbol *s=im->symbols+i;
    if(!s->name||!s->module||(s->flags&~1u)||
       ((s->function_id==0)==(s->variable_id==0)))
      return nvs_error(diagnostic,NTCG_E_UNSUPPORTED,"unknown or ambiguous seed symbol");
    if(s->function_id){
      if(s->section!=1||!s->size||s->offset>im->size||s->size>im->size-s->offset)
        return nvs_error(diagnostic,NTCG_E_INTERNAL,"invalid seed function extent");
      nf++;
    }
    else {size_t limit=s->section==2?im->rdata.size:s->section==3?im->data.size:0;
      if((s->section!=2&&s->section!=3)||s->offset>limit||s->size>limit-s->offset)
        return nvs_error(diagnostic,NTCG_E_UNSUPPORTED,"invalid seed data symbol");
      nv++;
    }
  }
  if(!nf)return nvs_error(diagnostic,NTCG_E_ENTRY,"seed image has no function roots");
  NvsFunction *fn=calloc(nf,sizeof *fn);NvsId *fm=calloc(nf,sizeof *fm),*vm=calloc(nv?nv:1,sizeof *vm);
  NvsRef *refs=calloc(nr?nr:1,sizeof *refs);NvsSite *sites=calloc(nr?nr:1,sizeof *sites);
  size_t *queue=calloc(nf,sizeof *queue);
  uint8_t *text=NULL,*ro=NULL,*rw=NULL;NtCodeSymbol *symbols=NULL;NtCodeReloc *relocs=NULL;
  int ok=0;unsigned error=NTCG_E_INTERNAL;const char *why="invalid seed image graph";
#define NVS_FAIL(code,message) do{error=(code);why=(message);goto done;}while(0)
  if(!fn||!fm||!vm||!refs||!sites||!queue)NVS_FAIL(NTCG_E_OOM,"seed graph allocation failed");
  size_t fi=0,vi=0;
  for(size_t i=0;i<im->symbol_count;i++){
    const NtCodeSymbol *s=im->symbols+i;
    if(s->function_id)fn[fi++]=(NvsFunction){i,s->offset,s->size,0,SIZE_MAX,0,0};
    else vm[vi++]=(NvsId){s->variable_id,i};
  }
  qsort(fn,nf,sizeof *fn,nvs_fn_order);
  size_t cursor=0;
  for(size_t i=0;i<nf;i++){
    if(fn[i].old_offset!=cursor)NVS_FAIL(NTCG_E_INTERNAL,"seed text not wholly partitioned by function extents");
    cursor+=fn[i].size;fm[i]=(NvsId){im->symbols[fn[i].symbol].function_id,i};
    if(policy==NOVA_SEED_ALL_EXPORTS&&(im->symbols[fn[i].symbol].flags&1))fn[i].roots|=2;
  }
  if(cursor!=im->size)NVS_FAIL(NTCG_E_INTERNAL,"seed trailing text is not described by a function");
  qsort(fm,nf,sizeof *fm,nvs_id_order);qsort(vm,nv,sizeof *vm,nvs_id_order);
  for(size_t i=1;i<nf;i++)if(fm[i].id==fm[i-1].id)NVS_FAIL(NTCG_E_INTERNAL,"duplicate seed function identity");
  for(size_t i=1;i<nv;i++)if(vm[i].id==vm[i-1].id)NVS_FAIL(NTCG_E_INTERNAL,"duplicate seed data identity");
  size_t entry_fn=nvs_owner(fn,nf,im->entry,1);
  if(entry_fn==SIZE_MAX)NVS_FAIL(NTCG_E_ENTRY,"seed entry has no function owner");
  fn[entry_fn].roots|=1;
  uint64_t old_base[4],new_base[4];
  if(!nvs_bases(im->size,im->rdata.size,im->data.size,old_base))
    NVS_FAIL(NTCG_E_RANGE,"seed original layout is not representable");
  for(size_t i=0;i<nr;i++){
    const NtCodeReloc *r=im->relocations+i;NvsRef *ref=refs+i;
    ref->owner=ref->function=ref->variable=ref->next=SIZE_MAX;
    if(r->kind!=NT_CODE_RELOC_REL32&&r->kind!=NT_CODE_RELOC_DIR64)
      NVS_FAIL(NTCG_E_UNSUPPORTED,"unknown seed relocation kind");
    ref->width=r->kind==NT_CODE_RELOC_REL32?4:8;
    if(r->source_section<1||r->source_section>3||
       ((r->target_function==0)==(r->target_variable==0)))
      NVS_FAIL(NTCG_E_UNSUPPORTED,"unknown or ambiguous seed relocation target");
    size_t limit=r->source_section==1?im->size:r->source_section==2?im->rdata.size:im->data.size;
    const uint8_t *bytes=r->source_section==1?im->bytes:r->source_section==2?im->rdata.bytes:im->data.bytes;
    if(r->offset>limit||ref->width>limit-r->offset)NVS_FAIL(NTCG_E_INTERNAL,"seed relocation site outside section");
    if(r->source_section==1){
      ref->owner=nvs_owner(fn,nf,r->offset,ref->width);
      if(ref->owner==SIZE_MAX)NVS_FAIL(NTCG_E_INTERNAL,"seed relocation crosses function extent");
    }
    uint64_t target=0;
    if(r->target_function){
      ref->function=nvs_lookup(fm,nf,r->target_function);
      if(ref->function==SIZE_MAX)NVS_FAIL(NTCG_E_UNSUPPORTED,"unresolved seed function reference");
      const NvsFunction *f=fn+ref->function;uint64_t delta=0;
      if(!nvs_add_offset(0,r->addend,f->size,0,&delta))
        NVS_FAIL(NTCG_E_UNSUPPORTED,"seed function reference escapes its function");
      target=f->old_offset+delta;result.function_references++;
      if(r->source_section!=1)fn[ref->function].roots|=4;
      else {ref->next=fn[ref->owner].first_edge;fn[ref->owner].first_edge=i;}
    }else{
      ref->variable=nvs_lookup(vm,nv,r->target_variable);
      if(ref->variable==SIZE_MAX)NVS_FAIL(NTCG_E_UNSUPPORTED,"unresolved seed data reference");
      const NtCodeSymbol *s=im->symbols+ref->variable;uint64_t delta=0;
      size_t target_limit=s->section==2?im->rdata.size:im->data.size;
      if(!nvs_add_offset(s->offset,r->addend,target_limit,1,&delta))
        NVS_FAIL(NTCG_E_RANGE,"seed data reference escapes its section");
      target=old_base[s->section]+delta;
    }
    if(r->kind==NT_CODE_RELOC_REL32){
      uint64_t expected=0;
      if(!nvs_rel32(old_base[r->source_section]+r->offset,target,&expected)||
         nvs_read(bytes+r->offset,4)!=expected)
        NVS_FAIL(NTCG_E_INTERNAL,"seed REL32 bytes disagree with typed reference");
    }else if(nvs_read(bytes+r->offset,8)!=0){
      NVS_FAIL(NTCG_E_UNSUPPORTED,"seed DIR64 was already materialized");
    }
    sites[i]=(NvsSite){r->source_section,r->offset,ref->width};
  }
  qsort(sites,nr,sizeof *sites,nvs_site_order);
  for(size_t i=1;i<nr;i++)if(sites[i].section==sites[i-1].section&&
      sites[i].offset<sites[i-1].offset+sites[i-1].width)
    NVS_FAIL(NTCG_E_INTERNAL,"overlapping seed relocation sites");
  size_t head=0,tail=0;
  for(size_t i=0;i<nf;i++)if(fn[i].roots){fn[i].live=1;queue[tail++]=i;}
  while(head<tail){
    size_t i=queue[head++];
    for(size_t edge=fn[i].first_edge;edge!=SIZE_MAX;edge=refs[edge].next){
      size_t target=refs[edge].function;
      if(target==SIZE_MAX)NVS_FAIL(NTCG_E_INTERNAL,"seed graph edge lost function identity");
      if(!fn[target].live){fn[target].live=1;queue[tail++]=target;}
    }
  }
  size_t new_size=0,kept=0,kept_relocs=0;
  for(size_t i=0;i<nf;i++)if(fn[i].live){
    fn[i].new_offset=new_size;new_size+=fn[i].size;kept++;
    if(fn[i].roots&1)result.roots_entry++;
    if(fn[i].roots&2)result.roots_exported++;
    if(fn[i].roots&4)result.roots_data++;
  }
  if(!nvs_bases(new_size,im->rdata.size,im->data.size,new_base))
    NVS_FAIL(NTCG_E_RANGE,"seed compacted layout is not representable");
  for(size_t i=0;i<nr;i++)if(refs[i].owner==SIZE_MAX||fn[refs[i].owner].live)kept_relocs++;
  text=malloc(new_size);ro=malloc(im->rdata.size?im->rdata.size:1);rw=malloc(im->data.size?im->data.size:1);
  symbols=calloc(kept+nv,sizeof *symbols);relocs=calloc(kept_relocs?kept_relocs:1,sizeof *relocs);
  if(!text||!ro||!rw||!symbols||!relocs)NVS_FAIL(NTCG_E_OOM,"seed compacted image allocation failed");
  if(im->rdata.size)memcpy(ro,im->rdata.bytes,im->rdata.size);
  if(im->data.size)memcpy(rw,im->data.bytes,im->data.size);
  for(size_t i=0;i<nf;i++)if(fn[i].live)memcpy(text+fn[i].new_offset,im->bytes+fn[i].old_offset,fn[i].size);
  size_t symbol_n=0;
  for(size_t i=0;i<im->symbol_count;i++){
    NtCodeSymbol s=im->symbols[i];
    if(s.function_id){
      size_t f=nvs_lookup(fm,nf,s.function_id);
      if(f==SIZE_MAX)NVS_FAIL(NTCG_E_INTERNAL,"seed symbol map lost function");
      if(!fn[f].live)continue;
      s.offset=fn[f].new_offset;
    }
    symbols[symbol_n++]=s;
  }
  size_t reloc_n=0;
  for(size_t i=0;i<nr;i++){
    const NtCodeReloc *original=im->relocations+i;const NvsRef *ref=refs+i;
    if(ref->owner!=SIZE_MAX&&!fn[ref->owner].live)continue;
    NtCodeReloc r=*original;
    if(ref->owner!=SIZE_MAX)r.offset=fn[ref->owner].new_offset+(r.offset-fn[ref->owner].old_offset);
    uint64_t target=0;
    if(ref->function!=SIZE_MAX){
      if(!fn[ref->function].live)NVS_FAIL(NTCG_E_INTERNAL,"retained seed reference targets discarded code");
      target=fn[ref->function].new_offset+(uint64_t)r.addend;
    }else{
      const NtCodeSymbol *s=im->symbols+ref->variable;uint64_t delta=0;
      size_t limit=s->section==2?im->rdata.size:im->data.size;
      if(!nvs_add_offset(s->offset,r.addend,limit,1,&delta))
        NVS_FAIL(NTCG_E_INTERNAL,"seed data target changed during compaction");
      target=new_base[s->section]+delta;
    }
    uint8_t *bytes=r.source_section==1?text:r.source_section==2?ro:rw;
    if(r.kind==NT_CODE_RELOC_REL32){
      uint64_t bits=0;
      if(!nvs_rel32(new_base[r.source_section]+r.offset,target,&bits))
        NVS_FAIL(NTCG_E_RANGE,"compacted seed REL32 is out of range");
      nvs_store(bytes+r.offset,4,bits);
    } /* DIR64 remains zero plus its typed metadata for artifact materialization. */
    relocs[reloc_n++]=r;
  }
  size_t new_entry=fn[entry_fn].new_offset+(im->entry-fn[entry_fn].old_offset);
  result.text_before=im->size;result.text_after=new_size;result.functions_before=nf;result.functions_kept=kept;
  result.relocations_before=nr;result.relocations_after=reloc_n;result.graph_complete=1;
  /* Transaction commit: names in retained rows transfer, discarded names die.
   * Failure above leaves original buffers, metadata and entry untouched. */
  for(size_t i=0;i<nf;i++)if(!fn[i].live){free(im->symbols[fn[i].symbol].name);free(im->symbols[fn[i].symbol].module);}
  free(im->bytes);free(im->rdata.bytes);free(im->data.bytes);free(im->symbols);free(im->relocations);
  im->bytes=text;im->size=im->capacity=new_size;im->entry=new_entry;text=NULL;
  im->rdata.bytes=ro;im->rdata.capacity=im->rdata.size;ro=NULL;
  im->data.bytes=rw;im->data.capacity=im->data.size;rw=NULL;
  im->symbols=symbols;im->symbol_count=im->symbol_capacity=symbol_n;symbols=NULL;
  im->relocations=relocs;im->relocation_count=im->relocation_capacity=reloc_n;relocs=NULL;
  if(stats)*stats=result;
  ok=1;
done:
  free(fn);free(fm);free(vm);free(refs);free(sites);free(queue);
  free(text);free(ro);free(rw);free(symbols);free(relocs);
  if(!ok)nvs_error(diagnostic,error,why);
#undef NVS_FAIL
  return ok;
}

/* Materialize only typed DIR64 rows after transferring section ownership to
 * NtArtifact. REL32 was already rechecked/repatched above. No PE limit changes. */
static int nova_seed_materialize_dir64(const NtCodeImage *im,NtArtifact *out,NtCodeDiagnostic *d){
  size_t count=0;for(size_t i=0;i<im->relocation_count;i++)if(im->relocations[i].kind==NT_CODE_RELOC_DIR64)count++;
  if(!count)return 1;
  uint64_t base[4];if(!nvs_bases(out->text.size,out->rdata.size,out->data.size,base))
    return nvs_error(d,NTCG_E_RANGE,"seed DIR64 layout overflow");
  NtBaseReloc *table=calloc(count,sizeof *table);
  if(!table)return nvs_error(d,NTCG_E_OOM,"seed DIR64 relocation allocation failed");
  size_t at=0;
  for(size_t i=0;i<im->relocation_count;i++){
    const NtCodeReloc *r=im->relocations+i;if(r->kind!=NT_CODE_RELOC_DIR64)continue;
    const NtCodeSymbol *target=NULL;
    for(size_t j=0;j<im->symbol_count;j++){
      const NtCodeSymbol *s=im->symbols+j;
      if((r->target_function&&s->function_id==r->target_function)||
         (r->target_variable&&s->variable_id==r->target_variable)){target=s;break;}
    }
    if(!target){free(table);return nvs_error(d,NTCG_E_INTERNAL,"seed DIR64 target disappeared");}
    uint64_t local=0;size_t limit=target->section==1?out->text.size:target->section==2?out->rdata.size:out->data.size;
    if(!nvs_add_offset(target->offset,r->addend,limit,1,&local)){free(table);return nvs_error(d,NTCG_E_RANGE,"seed DIR64 addend overflow");}
    uint64_t value=NT_PE_IMAGE_BASE+4096+base[target->section]+local;
    NtBuffer *section=r->source_section==1?&out->text:r->source_section==2?&out->rdata:&out->data;
    if(r->offset>section->size||8>section->size-r->offset){free(table);return nvs_error(d,NTCG_E_INTERNAL,"seed DIR64 site disappeared");}
    nvs_store(section->bytes+r->offset,8,value);
    table[at++]=(NtBaseReloc){r->source_section,r->offset,8};
  }
  out->base_relocations=table;out->base_relocation_count=at;return 1;
}
#endif

