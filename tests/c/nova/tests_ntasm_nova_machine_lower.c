#define main prior_pipeline_main
#include "tests_ntasm_machine_pipeline.c"
#undef main
static unsigned native,fixture;
static void native_mode_case(NovaHostImage *image,Run *r,const char *source,uint64_t want,uint64_t mode,uint64_t repeat){
  unsigned index=fixture++;fprintf(stderr,"NOVA_CASE %u want=%llu\n",index,(unsigned long long)want);
  cases++;uint64_t code=run(image,source,strlen(source),mode,repeat,r);
  if(code || r->runtime){
    fprintf(stderr,"NOVA_NATIVE case=%u code=%llu runtime=%llu stage=%llu line=%llu column=%llu record=%llu detail=%llu\n",index,(unsigned long long)code,(unsigned long long)r->runtime,(unsigned long long)r->report[8],(unsigned long long)r->report[0],(unsigned long long)r->report[1],(unsigned long long)r->report[3],(unsigned long long)r->report[2]);
    uint64_t bad=r->report[3],count=r->words[3];
    if(count<=(WORDS-10)/24 && bad && bad<=count){
      fprintf(stderr,"NOVA_MIR record=%llu",(unsigned long long)bad);
      for(unsigned f=0;f<24;f++)fprintf(stderr," %llu",(unsigned long long)r->words[10+(bad-1)*24+f]);
      fprintf(stderr,"\n");
    }
  }
  CHECK(code==0 && r->runtime==0,"Nova AST native lowering and PE generation");
  if(!code && !r->runtime){
    CHECK(r->report[11]==r->words[3],"every native MIR record preserves actual declaration NTIR coordinates");
    if(mode!=3)CHECK(r->report[12]==0,"no record claims a false NTIR/source coordinate correspondence");
    CHECK(r->length[0]>0 && r->length[0]<=TEXT,"Nova native PE bounded");
    if(r->length[0] && r->length[0]<=TEXT){
      uint64_t got=0;char why[256]={0};int rc=run_child((const uint8_t*)r->out,r->length[0],&got,why,sizeof why);
      if(rc || got!=want)fprintf(stderr,"NOVA_NATIVE got=%llu want=%llu rc=%d %s\n",(unsigned long long)got,(unsigned long long)want,rc,why);
      CHECK(rc==0 && got==want,"Nova native independent runtime oracle");
      if(!rc && got==want)native++;
    }
  }
}
static void native_case(NovaHostImage *image,Run *r,const char *source,uint64_t want){native_mode_case(image,r,source,want,1,0);}
static void declaration_case(NovaHostImage *image,Run *r,const char *source,const char *public_name,const char *fresh_private){
  cases++;uint64_t code=run(image,source,strlen(source),2,0,r);
  CHECK(code==0 && r->runtime==0,"named export lowers through the native declaration writer");
  uint64_t count=r->words[3],size=r->length[0],flag=r->report[10];
  CHECK(count<=(WORDS-10)/24 && size>0 && size<=TEXT && flag!=0,"declaration image and public flag bounded");
  if(code || r->runtime || count>(WORDS-10)/24 || !size || size>TEXT || !flag)return;
  CHECK(r->report[11]==count && r->report[12]==0,"all declaration/body record origins agree with a fresh NTIR read");
  const uint8_t *decl=(const uint8_t*)r->out;unsigned public_count=0,private_count=0;
  for(uint64_t a=1;a<=count;a++)if(r->words[10+(a-1)*24]==2051){
    uint64_t start=r->words[10+(a-1)*24+6],end=r->words[10+(a-1)*24+7];
    CHECK(start<=end && end<=size,"function name span lies in actual declaration text");if(start>end || end>size)continue;
    if(end-start==strlen(public_name) && !memcmp(decl+start,public_name,(size_t)(end-start))){public_count++;CHECK((r->words[10+(a-1)*24+13]&flag)!=0,"source public identity retained with MIR export flag");}
    if(fresh_private && end-start==strlen(fresh_private) && !memcmp(decl+start,fresh_private,(size_t)(end-start))){private_count++;CHECK((r->words[10+(a-1)*24+13]&flag)==0,"fresh internal identity remains private");}
    for(uint64_t b=a+1;b<=count;b++)if(r->words[10+(b-1)*24]==2051){
      uint64_t bs=r->words[10+(b-1)*24+6],be=r->words[10+(b-1)*24+7];
      CHECK(bs<=be && be<=size,"second function name bounded");
      if(bs<=be && be<=size)CHECK(end-start!=be-bs || memcmp(decl+start,decl+bs,(size_t)(end-start))!=0,"native declaration function symbols are unique");
    }
  }
  CHECK(public_count==1,"exactly one function retains the requested public name");
  if(fresh_private)CHECK(private_count==1,"deterministic fresh private name avoids all source exports");
  size_t bytes=(size_t)(10+count*24)*8;uint64_t *snapshot=malloc(bytes);uint8_t *names=malloc((size_t)size);
  CHECK(snapshot && names,"determinism snapshots allocated");
  if(snapshot && names){
    memcpy(snapshot,r->words,bytes);memcpy(names,decl,(size_t)size);
    code=run(image,source,strlen(source),2,0,r);
    CHECK(code==0 && r->runtime==0 && r->length[0]==size,"named export second lowering accepted");
    CHECK(!memcmp(snapshot,r->words,bytes) && !memcmp(names,r->out,(size_t)size),"public names, fresh private names and MIR are deterministic");
  }
  free(names);free(snapshot);
}int main(void){
  NtFInput inputs[PATHS_N+2];char *texts[PATHS_N+2]={0};size_t sizes[PATHS_N+2]={0};
  int all=1;
  for(unsigned i=0;i<PATHS_N+2;i++){
    const char *path=i==0?"tests/nova/tests/nova-machine-lower-entry.nova":i<PATHS_N?PATHS[i]:i==PATHS_N?"compiler/nova/frontend/nova_language_parse.nova":"compiler/nova/backend/nova/nova_machine_lower.nova";
    texts[i]=loadf(path,&sizes[i]);if(!texts[i])all=0;
    inputs[i]=(NtFInput){path,texts[i],sizes[i]};
  }
  NtArtifact art={0};NovaHostImage image={0};Run r={0};int ready=0;
  CHECK(all,"native producer source closure loaded");
  int compiled=all && nova_compile_many_v2(inputs,PATHS_N+2,&art);
  CHECK(compiled,"native producer compiles");
  if(!compiled){fprintf(stderr,"E%u %zu:%zu %s\n",art.error.code,art.error.line,art.error.column,art.error.message);goto cleanup;}
  CHECK(nova_host_map(&art,&image),"native producer mapped");if(!image.entry)goto cleanup;
  run_init(&r);ready=1;
  const char *positive[]={
    "module m;fn main()->u64{return 42;}",
    "module m;fn main()->u64{let mut x:u64=1;x=42;return x;}",
    "module m;fn main()->u64{let mut x:u64=6;let old:u64=x;x=7;return old*x;}",
    "module m;fn main()->u64{let mut x:u64=0;while x<6{x=x+1;}return x*7;}",
    "module m;fn main()->u64{let mut x:u64=0;let mut s:u64=0;while x<10{x=x+1;if x==3{continue;}if x==7{break;}s=s+x;}return s;}",
    "module m;fn main()->u64{let mut x:u64=0;let mut s:u64=0;while x<3{let mut y:u64=0;while y<4{y=y+1;if y==2{continue;}if y==4{break;}s=s+1;}x=x+1;}return s;}",
    "module m;fn add(a:u64,b:u64)->u64{return a+b;}fn main()->u64{let mut x:u64=40;x=add(x,2);return x;}",
    "module m;fn sum(n:u64)->u64{let mut saved:u64=n;if n==0{return saved;}else{let child:u64=sum(n-1);return saved+child;}}fn main()->u64{return sum(9);}",
    "module m;fn main()->u64{let mut x:u64=0;let mut s:u64=0;while x<4{let mut local:u64=x;local=local+1;s=s+local;x=x+1;}return s;}",
    "module m;fn main()->u64{let mut x:u64=5;if x==5{x=42;}else{x=43;}return x;}",
    "module m;fn main()->u64{let mut x:u64=6;{let mut x:u64=99;x=100;}return x*7;}",
    "module m;fn f(a:u64,b:u64,c:u64,d:u64,e:u64,f:u64)->u64{return a+b+c+d+e+f;}fn main()->u64{let mut x:u64=1;return f(x,2,3,4,5,27);}",
    "module m;fn main()->u64{let mut x:u64=0;while false{x=99;}return x+42;}",
    "module m;fn yes()->bool{return true;}fn main()->u64{if yes(){return 42;}else{return 0;}}",
    "module m;fn main()->i64{let mut x:i64=-2;x=x+1;return x;}",
    "module m;fn main()->u64{let mut b:bool=true;if b{b=false;}if b{return 0;}else{return 42;}}"
  };
  const uint64_t want[]={42,42,42,42,18,6,42,45,10,42,42,42,42,42,UINT64_MAX,42};
  for(unsigned i=0;i<sizeof positive/sizeof positive[0];i++)native_case(&image,&r,positive[i],want[i]);
  char many[8192];size_t used=(size_t)snprintf(many,sizeof many,"module many;fn main()->u64{");
  for(unsigned i=0;i<40;i++)used+=(size_t)snprintf(many+used,sizeof many-used,"let mut x%u:u64=%u;",i,i);
  used+=(size_t)snprintf(many+used,sizeof many-used,"x0=x39+3;return x0;}");
  CHECK(used<sizeof many,"forty local source bounded");if(used<sizeof many)native_case(&image,&r,many,42);
  const char *extra[]={
    "module m;fn trap(x:u64)->bool{return 1/x==0;}fn main()->u64{if false&&trap(0){return 0;}else{return 42;}}",
    "module m;fn trap(x:u64)->bool{return 1/x==0;}fn main()->u64{if true||trap(0){return 42;}else{return 0;}}",
    "module m;fn yes()->bool{return true;}fn main()->u64{if true&&yes(){return 42;}else{return 0;}}",
    "module m;fn yes()->bool{return true;}fn main()->u64{if false||yes(){return 42;}else{return 0;}}",
    "module m;fn main()->u64{let mut x:i64=-2;if x<0{return 42;}else{return 0;}}",
    "module m;fn main()->u64{let mut x:i64=-2;if 0>x{return 42;}else{return 0;}}",
    "module m;fn main()->u64{let mut x:i64=-2;if x<=-2{return 42;}else{return 0;}}",
    "module m;fn main()->u64{let mut x:i64=-2;if x>=-1{return 0;}else{return 42;}}",
    "module m;fn main()->u64{let mut x:u64=18446744073709551615;if x>0{return 42;}else{return 0;}}"
  };
  for(unsigned i=0;i<sizeof extra/sizeof extra[0];i++)native_case(&image,&r,extra[i],42);
  const char *corrupt="module m;fn helper(a:u64)->u64{return a;}fn main()->u64{let mut x:u64=6;x=helper(x);return x;}";
  for(unsigned mutation=0;mutation<12;mutation++){
    r.words[WORDS-1]=GUARD;cases++;
    uint64_t code=run(&image,corrupt,strlen(corrupt),4,mutation,&r);
    if(!code || r.runtime || r.report[13]!=1)fprintf(stderr,"NOVA_AST_MUTATION %u code=%llu runtime=%llu applied=%llu\n",mutation,(unsigned long long)code,(unsigned long long)r.runtime,(unsigned long long)r.report[13]);
    CHECK(r.report[13]==1,"AST/bound mutation witness applied");
    CHECK(code!=0 && r.runtime==0 && r.length[0]==0,"damaged AST or insufficient capacity refused without publication");
    CHECK(r.words[WORDS-1]==GUARD,"native writer preserves external end guard");
    CHECK(r.report[11]==0,"native lower clears a preexisting declaration length on refusal");
  }
  char stress[8192];size_t stress_size=(size_t)snprintf(stress,sizeof stress,"module stress;fn main()->u64{let mut x:u64=0;");
  for(unsigned i=0;i<500;i++)stress_size+=(size_t)snprintf(stress+stress_size,sizeof stress-stress_size,"x=x+1;");
  stress_size+=(size_t)snprintf(stress+stress_size,sizeof stress-stress_size,"return x;}");
  CHECK(stress_size<sizeof stress,"same-context ownership stress source bounded");
  if(stress_size<sizeof stress){
    native_mode_case(&image,&r,stress,500,3,64);
    CHECK(r.report[12]==64,"sixty-four native lowerings share one runtime context and one parsed AST");
  }  char graph[32768];size_t graph_size=(size_t)snprintf(graph,sizeof graph,"module graph;fn main()->u64{let mut sum:u64=0;");
  for(unsigned i=0;i<100;i++)graph_size+=(size_t)snprintf(graph+graph_size,sizeof graph-graph_size,
    "let mut i%u:u64=0;while i%u<2{if i%u==0{sum=sum+1;}else{sum=sum+2;}i%u=i%u+1;}",i,i,i,i,i);
  graph_size+=(size_t)snprintf(graph+graph_size,sizeof graph-graph_size,"return sum;}");
  CHECK(graph_size<sizeof graph,"one hundred loop/branch source bounded");
  if(graph_size<sizeof graph){
    native_case(&image,&r,graph,300);
    CHECK(r.words[7]>500,"native CFG exceeds declaration-sized scratch by hundreds of blocks");
    r.words[1024]=GUARD;r.words[WORDS-1]=GUARD;cases++;
    uint64_t code=run(&image,graph,strlen(graph),4,12,&r);
    CHECK(r.report[13]==1,"native body capacity refusal witness applied");
    CHECK(code!=0 && r.runtime==0 && r.length[0]==0 && r.report[11]==0,"native body exceeding logical MIR capacity is refused without publication");
    CHECK(r.words[1024]==GUARD && r.words[WORDS-1]==GUARD,"capacity guard and external end guard preserved");
  }  const char *named_export="module exported;export fn helper_public()->u64{return 42;}fn main()->u64{return helper_public();}";
  native_case(&image,&r,named_export,42);declaration_case(&image,&r,named_export,"helper_public",NULL);
  const char *collision="module collision;fn hidden()->u64{return 20;}export fn native_fn_1()->u64{return 21;}export fn native_fn_1_1()->u64{return 1;}fn main()->u64{return hidden()+native_fn_1()+native_fn_1_1();}";
  native_case(&image,&r,collision,42);declaration_case(&image,&r,collision,"native_fn_1","native_fn_1_2");  const char *negative[]={"module m;fn main()->u64{let x:u64=0;x=1;return x;}","module m;fn main()->u64{break;return 0;}","module m;fn main()->u64{return absent;}","module m;fn main()->u64{let mut x:u64=x;return x;}"};
  for(unsigned i=0;i<sizeof negative/sizeof negative[0];i++){cases++;uint64_t code=run(&image,negative[i],strlen(negative[i]),1,0,&r);CHECK(code!=0 && r.runtime==0,"invalid Nova refused without runtime fault");}
  CHECK(native==30,"all thirty true Nova-source PE executions completed");
cleanup:
  if(ready)run_free(&r);
  nova_host_unmap(&image);nt_artifact_free(&art);
  for(unsigned i=0;i<PATHS_N+2;i++)free(texts[i]);
  printf("NTASM_NOVA_MACHINE_LOWER checks=%u failures=%u cases=%u native=%u\n",checks,failures,cases,native);
  return failures?1:0;
}
