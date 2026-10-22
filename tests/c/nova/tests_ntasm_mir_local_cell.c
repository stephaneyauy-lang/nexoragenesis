#define main prior_pipeline_main
#include "tests_ntasm_machine_pipeline.c"
#undef main

static uint64_t lc_header,lc_stride;
static unsigned lc_native;
#define LC(r,n,f) ((r)->words[lc_header+((n)-1)*lc_stride+(f)])
static uint64_t lc_def(Run *r,uint64_t v) {
  for(uint64_t n=1;n<=r->words[3];n++)if(LC(r,n,4)==v && LC(r,n,0)!=2056)return n;
  return 0;
}
static int lc_line(const char *src,uint64_t line,const char *prefix) {
  while(line>1 && *src){if(*src++=='\n')line--;}
  return line==1 && strncmp(src,prefix,strlen(prefix))==0;
}
/* Transform real lowered declarations, preserving source provenance and CFG.
 * c* declarations become cells, s* declarations become stores to the first
 * cell in their function. Every source read has its own real copy record. */
static unsigned lc_cells(Run *r,const char *src) {
  if(!lc_stride || lc_header>=WORDS || r->words[3]>(WORDS-lc_header)/lc_stride)return 0;
  uint64_t first=0;unsigned cells=0;
  for(uint64_t n=1;n<=r->words[3];n++) {
    if(LC(r,n,0)==2051)first=0;
    if(LC(r,n,0)!=2056 || !LC(r,n,4))continue;
    int cell=lc_line(src,LC(r,n,2),"let c");
    int store=lc_line(src,LC(r,n,2),"let s:");
    if(!cell && !store)continue;
    uint64_t v=LC(r,n,4),d=lc_def(r,v);
    if(d<=n || LC(r,d,16)!=LC(r,n,16))return 0;
    /* Keep the real initializer coercion. Move only the unused declaration
     * placeholder after it, retaining sibling order and the original CFG. */
    uint64_t record[24];memcpy(record,&LC(r,n,0),sizeof record);
    uint64_t ordinal=LC(r,n,17);
    memmove(&LC(r,n,0),&LC(r,n+1,0),(size_t)(d-n)*lc_stride*8);
    memcpy(&LC(r,d,0),record,sizeof record);
    for(uint64_t q=n;q<=d;q++)LC(r,q,17)=ordinal+q-n;
    for(unsigned f=4;f<=15;f++)LC(r,d,f)=0;
    LC(r,d,9)=record[9];LC(r,d,10)=record[10];LC(r,d,11)=0;LC(r,d,12)=2;LC(r,d,13)=2;
    if(cell){
      uint64_t address=++r->words[6];
      LC(r,d,0)=2086;LC(r,d,4)=address;LC(r,d,5)=v;LC(r,d,8)=1;LC(r,d,14)=record[9];LC(r,d,15)=record[10];
      LC(r,d,9)=64;LC(r,d,10)=0;
      /* Only value operands after this declaration are remapped; record links
       * and the initializer snapshot are not addresses. These fixture bodies
       * use values in copy/binary/convert/return/call operands. */
      for(uint64_t q=d+1;q<=r->words[3];q++){
        uint64_t kind=LC(r,q,0);
        for(unsigned a=0;a<3 && a<LC(r,q,8);a++){
          int value=(kind==2069 || kind==2070 || kind==2071 || kind==2073 || kind==2074 || kind==2075 || kind==2077 || kind==2067 || kind==2068);
          if(kind==2079)value=a==0;
          if(kind==2076)value=a>0;
          if(value && LC(r,q,5+a)==v)LC(r,q,5+a)=address;
        }
      }
      if(!first)first=address;
      cells++;
    }else{
      if(!first)return 0;
      LC(r,d,0)=2068;LC(r,d,5)=first;LC(r,d,6)=v;LC(r,d,8)=2;LC(r,d,14)=27;
    }
    n=d;
  }
  for(uint64_t n=1;n<=r->words[3];n++)if(LC(r,n,0)==2069) {
    uint64_t d=lc_def(r,LC(r,n,5));
    if(d && LC(r,d,0)==2086){LC(r,n,0)=2067;LC(r,n,12)=1;LC(r,n,13)=0;LC(r,n,14)=26;}
  }
  r->words[2]=2;
  return cells;
}static void lc_execute(NovaHostImage *img,Run *r,const char *src,uint64_t want) {
  cases++;
  uint64_t code=run(img,src,strlen(src),5,0,r);
  if(code || r->runtime)fprintf(stderr,"LOCAL_CELL PE code=%llu runtime=%llu record=%llu\n",(unsigned long long)code,(unsigned long long)r->runtime,(unsigned long long)r->report[0]);
  if(code && r->words[3] && r->words[3]<=(WORDS-lc_header)/lc_stride) {
    uint64_t bad=r->report[0];
    if(bad>0 && bad<=r->words[3]){
      for(unsigned pass=0;pass<2;pass++){
        uint64_t rec=pass?lc_def(r,LC(r,bad,5)):bad;
        if(rec && rec<=r->words[3]){fprintf(stderr,"LOCAL_CELL RECORD %llu",(unsigned long long)rec);for(unsigned f=0;f<24;f++)fprintf(stderr," %llu",(unsigned long long)LC(r,rec,f));fprintf(stderr,"\n");}
      }
    }
  }  CHECK(code==0 && r->runtime==0,"local-cell verified PE generation");
  if(!code && !r->runtime)CHECK(r->length[0]>0 && r->length[0]<=TEXT,"local-cell PE output bounded");
  if(!code && !r->runtime && r->length[0]>0 && r->length[0]<=TEXT){
    uint64_t got=0;char why[256]={0};int rc=run_child((const uint8_t *)r->out,r->length[0],&got,why,sizeof why);
    if(rc || got!=want)fprintf(stderr,"LOCAL_CELL got=%llu want=%llu rc=%d %s\n",(unsigned long long)got,(unsigned long long)want,rc,why);
    CHECK(rc==0 && got==want,"local-cell native oracle");
    if(rc==0 && got==want)lc_native++;
  }
}
int main(void) {
  NtFInput inputs[PATHS_N];char *texts[PATHS_N]={0};size_t sizes[PATHS_N];
  int all=1;
  for(unsigned i=0;i<PATHS_N;i++){
    const char *p=i?PATHS[i]:"tests/nova/tests/mir-local-cell-entry.nova";
    texts[i]=loadf(p,&sizes[i]);if(!texts[i])all=0;
    inputs[i]=(NtFInput){p,texts[i],sizes[i]};
  }
  NtArtifact art={0};NovaHostImage img={0};Run r={0};int run_ready=0;
  CHECK(all,"local-cell source closure loaded");
  int compiled=all && nova_compile_many_v2(inputs,PATHS_N,&art);
  CHECK(compiled,"local-cell gate compiled");
  if(!compiled){fprintf(stderr,"E%u %s\n",art.error.code,art.error.message);goto cleanup;}
  CHECK(nova_host_map(&art,&img),"local-cell gate mapped");
  if(!img.entry)goto cleanup;
  run_init(&r);run_ready=1;run(&img,"",0,0,0,&r);
  lc_header=r.words[0];lc_stride=r.words[1];
  CHECK(lc_header>0 && lc_header<WORDS && lc_stride==24,"local-cell schema from owner");
  if(!lc_header || lc_header>=WORDS || lc_stride!=24)goto cleanup;
  const char *src="module cells\ntarget x86_64-nexora-uefi\ndefault_abi efi-x64-v0\nsection .text {\nexport fn main()->u64 effects {} clobbers {rax} {\nlet spare:u64=0;\nlet c:u64=6;\nlet old:u64=(c);\nlet s:u64=7;\nreturn old*(c);\n}\n}\n";
  uint64_t initial=run(&img,src,strlen(src),3,0,&r);
  CHECK(initial==0 && r.runtime==0,"cell fixture lowered before mutation");
  if(initial || r.runtime || r.words[3]>(WORDS-lc_header)/lc_stride)goto cleanup;
  unsigned count=lc_cells(&r,src);CHECK(count==1,"one real cell witness");
  size_t bytes=(size_t)(lc_header+r.words[3]*lc_stride)*8;
  uint64_t *clean=malloc(bytes);CHECK(clean!=NULL,"cell snapshot allocated");
  if(clean){
    memcpy(clean,r.words,bytes);lc_execute(&img,&r,src,42);
    uint64_t cell=0,load=0,store=0;
    for(uint64_t n=1;n<=r.words[3];n++){if(LC(&r,n,0)==2086)cell=n;if(LC(&r,n,0)==2067)load=n;if(LC(&r,n,0)==2068)store=n;}
    CHECK(cell && load && store,"cell/load/store witnesses");
    if(cell && load && store)for(unsigned m=0;m<13;m++){
      memcpy(r.words,clean,bytes);
      if(m==0)r.words[2]=1;
      if(m==1)r.words[2]=4;
      if(m==2)LC(&r,cell,14)=128;
      if(m==3)LC(&r,load,9)=32;
      if(m==4)LC(&r,store,10)=1;
      if(m==5)LC(&r,cell,5)=LC(&r,cell,4);
      if(m==6)LC(&r,load,5)=r.words[6]+1;
      if(m==7){LC(&r,load,0)=2069;LC(&r,load,14)=1;}
      if(m==8)LC(&r,cell,20)=5;
      if(m==9)LC(&r,cell,13)=1;
      if(m==10)LC(&r,cell,15)=2;
      if(m==11)LC(&r,store,6)=LC(&r,cell,4);
      if(m==12){
        uint64_t before=0,future=0;
        for(uint64_t q=1;q<=r.words[3];q++)if(LC(&r,q,0)==2056 && LC(&r,q,4)){if(q<cell)before=q;else if(!future)future=q;}
        CHECK(before && future,"early placeholder and future scalar witnesses");
        if(before && future){LC(&r,before,4)=LC(&r,future,4);LC(&r,cell,5)=LC(&r,future,4);}
      }
      uint64_t code=run(&img,src,strlen(src),12,0,&r);cases++;
      CHECK(code!=0 && r.runtime==0,"local-cell malformed/escape/version refused");
    }
    /* A CELL ID BEYOND THE VALUE COUNTER. This one does NOT reach the cell
     * pass: the id is pushed past the counter, so the image is refused by the
     * rule that bounds a produced value -- the rule that runs before the cell
     * pass -- with the code and the record it always had. It pins that
     * refusal, which is the same before and after the index and does not
     * depend on the index at all. The fallback itself is exercised by the
     * sparse-id scenario below, whose id is above the record count and inside
     * the counter. 941 is machine_ir.nova's E_VALUE. */
    memcpy(r.words,clean,bytes);
    if(cell){
      LC(&r,cell,4)=r.words[6]+1;
      uint64_t scode=run(&img,src,strlen(src),12,0,&r);cases++;
      if(scode!=941||r.runtime!=0||r.report[3]!=cell)
        fprintf(stderr,"LOCAL_CELL BEYOND code=%llu runtime=%llu record=%llu want=941/%llu\n",
          (unsigned long long)scode,(unsigned long long)r.runtime,
          (unsigned long long)r.report[3],(unsigned long long)cell);
      CHECK(scode==941 && r.runtime==0 && r.report[3]==cell,
            "cell id beyond the value counter refused with E_VALUE at the cell record");
    }
    /* THE SPARSE CELL ID: AN ID THE INDEX CANNOT HOLD.
     *
     * The index is bounded by the RECORD count, so a cell id above it stays
     * out of the table and the uses of that id go through the original scan.
     * The id is taken above BOTH the value counter and the record count, with
     * a margin, and the counter is raised to it so the id is inside the value
     * space and the pass that bounds a produced value does not refuse the
     * image before the cell pass is reached. Both bounds are checked here,
     * because a scenario that does not reach the fallback measures nothing.
     *
     * Every LOAD and STORE whose first operand is the old cell id is
     * remapped onto the sparse id, and the number of remappings is counted:
     * the users are MEASURED here, not assumed, and the image must stay
     * coherent -- the cell carries the sparse id and every use of it points
     * at the same id, or the uniqueness rule would refuse the image and the
     * scenario would measure that refusal instead.
     *
     * The verdict is expected to be 0 BY THE RULES -- the cell is found, and
     * the checks its presence triggers are the ones the clean image already
     * passes -- and that expectation is NOT a measurement: the parent's first
     * run of this fixture is on the verifier of BEFORE, to measure that
     * implementation's answer, and the second is on the verifier of now. */
    memcpy(r.words,clean,bytes);
    int sparse_ran=0;
    if(cell){
      uint64_t old_id=LC(&r,cell,4);
      uint64_t base=r.words[6]>r.words[3]?r.words[6]:r.words[3];
      int overflow=base>UINT64_MAX-17;
      CHECK(!overflow,"the sparse cell id does not overflow");
      if(!overflow){
        uint64_t sparse=base+17;
        r.words[6]=sparse;
        CHECK(sparse>r.words[3],"the sparse cell id is above the record count");
        CHECK(sparse<=r.words[6],"the sparse cell id is inside the value counter");
        if(sparse>r.words[3]&&sparse<=r.words[6]){
          LC(&r,cell,4)=sparse;
          uint64_t remapped=0;
          for(uint64_t n=1;n<=r.words[3];n++){
            uint64_t kind=LC(&r,n,0);
            if((kind==2067||kind==2068)&&LC(&r,n,5)==old_id){LC(&r,n,5)=sparse;remapped++;}
          }
          CHECK(remapped>0,"the cell id has load or store users remapped");
          uint64_t carriers=0;
          for(uint64_t n=1;n<=r.words[3];n++)if(LC(&r,n,4)==sparse)carriers++;
          CHECK(carriers==1,"the sparse id is carried by the cell alone");
          if(remapped>0&&carriers==1){
            uint64_t code=run(&img,src,strlen(src),12,0,&r);cases++;sparse_ran=1;
            if(code!=0||r.runtime!=0)
              fprintf(stderr,"LOCAL_CELL SPARSEID code=%llu runtime=%llu remapped=%llu\n",
                (unsigned long long)code,(unsigned long long)r.runtime,
                (unsigned long long)remapped);
            CHECK(code==0 && r.runtime==0,"sparse cell id accepted like a dense one");
          }
        }
      }
    }
    CHECK(sparse_ran,"the sparse cell id scenario ran");
    /* THE CARRIER INDEX, AND THE THREE ANSWERS IT HAS TO GIVE.
     *
     * The uniqueness rule of a cell asks for the FIRST OTHER record that
     * carries the cell's value id, and it asked for it by walking the whole
     * image once per cell. The index answers the same record, and three
     * shapes have to be answered, each naming a DIFFERENT record:
     *
     *   1. the first carrier is an ordinary record BEFORE the cell: the
     *      refusal names that ordinary record, not the cell;
     *   2. the cell is the first carrier and an ordinary record AFTER it
     *      carries the same value: the refusal names that later record,
     *      which is the SECOND carrier;
     *   3. the value id is SPARSE -- above the record count, so no table can
     *      hold it: the original walk is kept, and it answers the same.
     *
     * 941 is machine_ir.nova's E_VALUE, and the record is read out of the
     * rule that produces it, not out of the index. The unit record is the
     * ordinary carrier: it has no operands, so giving it a produced value
     * moves nothing else in the image. */
    {
      uint64_t unit=0,later=0;
      memcpy(r.words,clean,bytes);
      for(uint64_t n=1;n<=r.words[3];n++)if(LC(&r,n,0)==2048){unit=n;break;}
      CHECK(unit==1,"the unit record is the ordinary carrier witness");
      if(cell&&unit){
        uint64_t vid=LC(&r,cell,4);
        LC(&r,unit,4)=vid;
        uint64_t code=run(&img,src,strlen(src),12,0,&r);cases++;
        if(code!=941||r.runtime!=0||r.report[3]!=unit)
          fprintf(stderr,"LOCAL_CELL FIRST code=%llu runtime=%llu record=%llu want=941/%llu\n",
            (unsigned long long)code,(unsigned long long)r.runtime,
            (unsigned long long)r.report[3],(unsigned long long)unit);
        CHECK(code==941 && r.runtime==0 && r.report[3]==unit,
              "a duplicated value is refused at the FIRST carrier, whatever its kind");
      }
      /* THE SECOND CARRIER: the cell carries the value first and an ordinary
       * record after it carries the same value. The refusal names the later
       * record, which is the second carrier and not the first. */
      memcpy(r.words,clean,bytes);
      for(uint64_t n=cell+1;n<=r.words[3];n++)if(LC(&r,n,0)==2067){later=n;break;}
      CHECK(later>cell,"an ordinary record after the cell is the second carrier witness");
      if(cell&&later>cell){
        LC(&r,later,4)=LC(&r,cell,4);
        uint64_t code=run(&img,src,strlen(src),12,0,&r);cases++;
        if(code!=941||r.runtime!=0||r.report[3]!=later)
          fprintf(stderr,"LOCAL_CELL SECOND code=%llu runtime=%llu record=%llu want=941/%llu\n",
            (unsigned long long)code,(unsigned long long)r.runtime,
            (unsigned long long)r.report[3],(unsigned long long)later);
        CHECK(code==941 && r.runtime==0 && r.report[3]==later,
              "a duplicated value is refused at the SECOND carrier");
      }
      /* THE SPARSE ID, DUPLICATED: THE ORIGINAL WALK IS KEPT. The id is above
       * the record count, so no table holds it, and the walk answers the
       * unit that carries it. */
      memcpy(r.words,clean,bytes);
      if(cell&&unit){
        uint64_t old_id=LC(&r,cell,4);
        uint64_t base=r.words[6]>r.words[3]?r.words[6]:r.words[3];
        uint64_t sparse=base+17;
        CHECK(sparse>r.words[3],"the duplicated sparse id is above the record count");
        if(sparse>r.words[3]){
          r.words[6]=sparse;
          LC(&r,cell,4)=sparse;
          uint64_t remapped=0;
          for(uint64_t n=1;n<=r.words[3];n++){
            uint64_t kind=LC(&r,n,0);
            if((kind==2067||kind==2068)&&LC(&r,n,5)==old_id){LC(&r,n,5)=sparse;remapped++;}
          }
          CHECK(remapped>0,"the sparse cell id has load or store users remapped");
          LC(&r,unit,4)=sparse;
          uint64_t code=run(&img,src,strlen(src),12,0,&r);cases++;
          if(code!=941||r.runtime!=0||r.report[3]!=unit)
            fprintf(stderr,"LOCAL_CELL SPARSEDUP code=%llu runtime=%llu record=%llu want=941/%llu\n",
              (unsigned long long)code,(unsigned long long)r.runtime,
              (unsigned long long)r.report[3],(unsigned long long)unit);
          CHECK(code==941 && r.runtime==0 && r.report[3]==unit,
                "a duplicated sparse value id is refused at its first carrier");
        }
      }
    }
    memcpy(r.words,clean,bytes);lc_execute(&img,&r,src,42);free(clean);
  }
  /* More locals than physical register families; each owns distinct storage. */
  char many[8192];size_t used=(size_t)snprintf(many,sizeof many,"module many\ntarget x86_64-nexora-uefi\nsection .text { export fn main()->u64 effects {} clobbers {rax} {\n");
  for(unsigned i=0;i<32;i++)used+=(size_t)snprintf(many+used,sizeof many-used,"let c%u:u64=%u;\n",i,i+1);
  used+=(size_t)snprintf(many+used,sizeof many-used,"return (c0)+(c31);\n} }\n");
  CHECK(used<sizeof many,"many cells fixture bounded");
  uint64_t many_code=run(&img,many,used,3,0,&r);
  CHECK(many_code==0 && r.runtime==0,"32 locals base lowered");
  if(!many_code && !r.runtime){CHECK(lc_cells(&r,many)==32,"32 independent cell witnesses");lc_execute(&img,&r,many,33);}
  /* THE CELL INDEX: THE FIRST MATCH WINS, AND A DUPLICATE IS STILL REFUSED.
   * Two cells carrying the SAME value id: the index keeps the FIRST of them,
   * and the uniqueness rule still refuses the image, naming the LATER of the
   * two records. The code and the record are the ones the scan produced, and
   * they are read here from the rule that produces them, not from the index:
   * 941 is machine_ir.nova's E_VALUE, and the record is the one the
   * uniqueness loop finds first. */
  if(!many_code && !r.runtime && r.words[3]<=(WORDS-lc_header)/lc_stride){
    size_t mbytes=(size_t)(lc_header+r.words[3]*lc_stride)*8;
    uint64_t *snap=malloc(mbytes);
    CHECK(snap!=NULL,"many-cell snapshot allocated");
    int dup_ran=0;
    if(snap){
      memcpy(snap,r.words,mbytes);
      uint64_t c1=0,c2=0;
      for(uint64_t n=1;n<=r.words[3];n++)if(LC(&r,n,0)==2086){if(!c1)c1=n;else if(!c2)c2=n;}
      CHECK(c1&&c2,"two cell witnesses for the duplicate row");
      if(c1&&c2){
        uint64_t later=c1>c2?c1:c2;
        LC(&r,c2,4)=LC(&r,c1,4);
        uint64_t code=run(&img,many,used,12,0,&r);cases++;dup_ran=1;
        if(code!=941||r.runtime!=0||r.report[3]!=later)
          fprintf(stderr,"LOCAL_CELL DUP code=%llu runtime=%llu record=%llu want=941/%llu\n",
            (unsigned long long)code,(unsigned long long)r.runtime,
            (unsigned long long)r.report[3],(unsigned long long)later);
        CHECK(code==941 && r.runtime==0 && r.report[3]==later,
              "duplicate cell id refused with E_VALUE at the later cell record");
        memcpy(r.words,snap,mbytes);
      }
      free(snap);
    }
    CHECK(dup_ran,"the duplicate cell id scenario ran");
  }
  const char *programs[]={
    "module callcell\ntarget x86_64-nexora-uefi\ndefault_abi efi-x64-v0\nsection .text {\nfn helper()->u64 effects {} clobbers {rax} {return 99;}\nexport fn main()->u64 effects {} clobbers {rax} {\nlet spare:u64=0;\nlet c:u64=6;\nlet old:u64=(c);\nlet ignored:u64=helper();\nlet s:u64=7;\nreturn old*(c);\n}\n}\n",
    "module recursivecell\ntarget x86_64-nexora-uefi\ndefault_abi efi-x64-v0\nsection .text {\nfn sum(in n:u64 @rcx)->u64 effects {} clobbers {rax} {\nlet c:u64=n;\nif (n==0) {return (c);} else {\nlet result:u64=sum(n-1);\nreturn (c)+result;\n}\n}\nexport fn main()->u64 effects {} clobbers {rax} {return sum(4);}\n}\n",
    "module loopcell\ntarget x86_64-nexora-uefi\ndefault_abi efi-x64-v0\nsection .text {\nexport fn main()->u64 effects {} clobbers {rax} {\nlet c:u64=0;\nagain:\nif ((c)<4) {\nlet s:u64=(c)+1;\njmp again;\n} else {return (c);}\nreturn (c);\n}\n}\n"
  };
  const uint64_t wants[]={42,10,4};
  for(unsigned p=0;p<3;p++) {
    uint64_t code=run(&img,programs[p],strlen(programs[p]),3,0,&r);
    if(code || r.runtime)fprintf(stderr,"LOCAL_CELL fixture%u lower code=%llu runtime=%llu stage=%llu\n",p,(unsigned long long)code,(unsigned long long)r.runtime,(unsigned long long)r.report[8]);
    CHECK(code==0 && r.runtime==0,"call/recursion/loop base lowered");
    if(!code && !r.runtime){CHECK(lc_cells(&r,programs[p])==1,"call/recursion/loop cell witness");lc_execute(&img,&r,programs[p],wants[p]);}
  }
  const char *branches="module branchcells\ntarget x86_64-nexora-uefi\nsection .text {\nexport fn main()->u64 effects {} clobbers {rax} {\nlet cbase:u64=6;\nif (0==1) {\nlet cbranch:u64=7;\nreturn (cbranch);\n} else {return (cbase);}\n}\n}\n";
  uint64_t bcode=run(&img,branches,strlen(branches),3,0,&r);
  CHECK(bcode==0 && r.runtime==0,"dominance fixture lowered");
  if(!bcode && !r.runtime){
    CHECK(lc_cells(&r,branches)==2,"two branch cell witnesses");lc_execute(&img,&r,branches,6);
    uint64_t branchcell=0,lastload=0;
    for(uint64_t n=1;n<=r.words[3];n++){if(LC(&r,n,0)==2086)branchcell=n;if(LC(&r,n,0)==2067)lastload=n;}
    CHECK(branchcell && lastload,"dominance mutation witnesses");
    if(branchcell && lastload){LC(&r,lastload,5)=LC(&r,branchcell,4);CHECK(run(&img,branches,strlen(branches),12,0,&r)!=0 && r.runtime==0,"non-dominating branch cell refused");}
  }
  const char *narrow_types[]={"u8","u16","u32","i8","i16","i32"};
  const char *narrow_initial[]={"255","65535","4294967295","-2","-2","-2"};
  const uint64_t narrow_wants[]={0,0,0,UINT64_MAX,UINT64_MAX,UINT64_MAX};
  for(unsigned t=0;t<6;t++){
    char src_t[1024];int written=snprintf(src_t,sizeof src_t,
      "module narrow\ntarget x86_64-nexora-uefi\nsection .text {\nexport fn main()->%s effects {} clobbers {rax} {\nlet c:%s=%s;\nlet old:%s=(c);\nlet s:%s=1;\nreturn old+(c);\n}\n}\n",
      narrow_types[t],narrow_types[t],narrow_initial[t],narrow_types[t],narrow_types[t]);
    CHECK(written>0 && (size_t)written<sizeof src_t,"narrow cell source bounded");
    uint64_t code=run(&img,src_t,strlen(src_t),3,0,&r);
    if(code || r.runtime)fprintf(stderr,"LOCAL_CELL narrow%s lower code=%llu runtime=%llu stage=%llu line=%llu column=%llu\n",narrow_types[t],(unsigned long long)code,(unsigned long long)r.runtime,(unsigned long long)r.report[8],(unsigned long long)r.report[0],(unsigned long long)r.report[1]);
    CHECK(code==0 && r.runtime==0,"narrow signed/unsigned fixture lowered");
    if(!code && !r.runtime){CHECK(lc_cells(&r,src_t)==1,"narrow typed cell witness");lc_execute(&img,&r,src_t,narrow_wants[t]);}
  }
  const char *reset="module resetcell\ntarget x86_64-nexora-uefi\nsection .text {\nexport fn main()->u64 effects {} clobbers {rax} {\nlet c:u64=0;\nagain:\nlet cinner:u64=(c);\nlet s:u64=(c)+1;\nif ((cinner)==2) {return (c);} else {jmp again;}\nreturn 0;\n}\n}\n";
  uint64_t reset_code=run(&img,reset,strlen(reset),3,0,&r);
  CHECK(reset_code==0 && r.runtime==0,"loop initialization source lowered");
  if(!reset_code && !r.runtime){CHECK(lc_cells(&r,reset)==2,"outer and repeatedly initialized inner cells");lc_execute(&img,&r,reset,3);}
  const char *arguments="module cellargs\ntarget x86_64-nexora-uefi\ndefault_abi efi-x64-v0\nsection .text {\nfn helper(in a:u64 @rcx)->u64 effects {} clobbers {rax} {return a;}\nexport fn main()->u64 effects {} clobbers {rax} {\nlet c:u64=6;\nlet result:u64=helper((c));\nreturn (c);\n}\n}\n";
  uint64_t arg_code=run(&img,arguments,strlen(arguments),3,0,&r);
  CHECK(arg_code==0 && r.runtime==0,"local read call argument source lowered");
  if(!arg_code && !r.runtime){
    CHECK(lc_cells(&r,arguments)==1,"call argument cell witness");lc_execute(&img,&r,arguments,6);
    uint64_t call=0,lastload=0;
    for(uint64_t n=1;n<=r.words[3];n++){if(LC(&r,n,0)==2076)call=n;if(LC(&r,n,0)==2067)lastload=n;}
    CHECK(call && lastload>call,"future read and call argument witnesses");
    if(call && lastload>call){LC(&r,call,6)=LC(&r,lastload,4);CHECK(run(&img,arguments,strlen(arguments),12,0,&r)!=0 && r.runtime==0,"future load as call argument refused");}
  }
  const char *argbranches="module branchargs\ntarget x86_64-nexora-uefi\ndefault_abi efi-x64-v0\nsection .text {\nfn helper(in a:u64 @rcx)->u64 effects {} clobbers {rax} {return a;}\nexport fn main()->u64 effects {} clobbers {rax} {\nlet c:u64=6;\nif (0==1) {\nlet snapshot:u64=(c);\nreturn snapshot;\n} else {return helper((c));}\n}\n}\n";
  uint64_t ab_code=run(&img,argbranches,strlen(argbranches),3,0,&r);
  CHECK(ab_code==0 && r.runtime==0,"branch call argument source lowered");
  if(!ab_code && !r.runtime){
    CHECK(lc_cells(&r,argbranches)==1,"branch argument cell witness");lc_execute(&img,&r,argbranches,6);
    uint64_t call=0,firstload=0;
    for(uint64_t n=1;n<=r.words[3];n++){if(LC(&r,n,0)==2076)call=n;if(!firstload && LC(&r,n,0)==2067)firstload=n;}
    CHECK(call && firstload && firstload<call,"non-dominating snapshot and call witnesses");
    if(call && firstload){LC(&r,call,6)=LC(&r,firstload,4);CHECK(run(&img,argbranches,strlen(argbranches),12,0,&r)!=0 && r.runtime==0,"non-dominating load as call argument refused");}
  }
  /* Previous minor remains readable when the image contains no new kind. */
  const char *plain="module old\ntarget x86_64-nexora-uefi\nsection .text { export fn main()->u64 effects {} clobbers {rax} {return 42;} }";
  uint64_t old_code=run(&img,plain,strlen(plain),3,0,&r);
  CHECK(old_code==0 && r.runtime==0,"old minor fixture lowered");
  if(!old_code && !r.runtime){r.words[2]=1;lc_execute(&img,&r,plain,42);}
  CHECK(lc_native==17,"all seventeen local-cell and compatibility PE executions completed");
cleanup:
  if(run_ready)run_free(&r);
  nova_host_unmap(&img);nt_artifact_free(&art);
  for(unsigned i=0;i<PATHS_N;i++)free(texts[i]);
  printf("NTASM_MIR_LOCAL_CELL checks=%u failures=%u cases=%u\n",checks,failures,cases);
  return failures?1:0;
}
