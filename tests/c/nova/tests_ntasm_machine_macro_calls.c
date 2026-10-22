/* Explicitly supplied caller expressions preserve hygiene; implicit capture stays rejected. */
#define main original_pipeline_gate_main
#include "tests_ntasm_machine_pipeline.c"
#undef main

int main(void) {
  NtFInput in[PATHS_N];char *sources[PATHS_N];size_t sizes[PATHS_N];
  for(unsigned i=0;i<PATHS_N;i++){sources[i]=loadf(PATHS[i],&sizes[i]);if(!sources[i])return 2;in[i]=(NtFInput){PATHS[i],sources[i],sizes[i]};}
  NtArtifact art={0};NovaHostImage image={0};
  if(!nova_compile_many_v2(in,PATHS_N,&art)||!nova_host_map(&art,&image)){ fprintf(stderr,"COMPILE E%u source=%u line=%zu col=%zu %s\n",art.error.code,art.error.source_index,art.error.line,art.error.column,art.error.message); nt_artifact_free(&art);for(unsigned i=0;i<PATHS_N;i++)free(sources[i]);return 2;}
  const char *paths[]={"examples/ntasm-v0/common-pipeline/multi-explicit-app.ntasm","examples/ntasm-v0/c-bootstrap-multi/app.ntasm"};
  const uint64_t expected[]={0,374};Run r;run_init(&r);
  for(unsigned i=0;i<2;i++){
    size_t n=0;char *src=loadf(paths[i],&n);if(!src){failures++;continue;}
    uint64_t code=run(&image,src,n,3,0,&r);
    printf("MACRO_CALL kind=%s code=%llu runtime=%llu stage=%llu\n",i?"implicit-capture":"explicit-argument",(unsigned long long)code,(unsigned long long)r.runtime,(unsigned long long)r.report[8]);
    printf("MACRO_LOCATION line=%llu col=%llu code=%llu node=%llu\n",(unsigned long long)r.report[0],(unsigned long long)r.report[1],(unsigned long long)r.report[2],(unsigned long long)r.report[3]);
    CHECK(code==expected[i]&&r.runtime==0,"explicit caller argument accepted; implicit caller capture refused without runtime fault");free(src);
  }
  run_free(&r);nova_host_unmap(&image);nt_artifact_free(&art);for(unsigned i=0;i<PATHS_N;i++)free(sources[i]);
  printf("NTASM_NOVA_MACHINE_MACRO_CALLS checks=%u failures=%u\n",checks,failures);return failures?1:0;
}
