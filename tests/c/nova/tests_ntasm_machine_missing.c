/* Regression cases accepted by the C frontend and needed by the common producer. */
#define main machine_ir_existing_gate_main
#include "tests_ntasm_machine_ir.c"
#undef main

int main(void) {
  NtFInput inputs[PATHS_N];char *sources[PATHS_N];size_t sizes[PATHS_N];
  for(unsigned i=0;i<PATHS_N;i++){sources[i]=loadf(PATHS[i],&sizes[i]);if(!sources[i])return 2;inputs[i]=(NtFInput){PATHS[i],sources[i],sizes[i]};}
  NtArtifact art={0};NovaHostImage image={0};
  if(!nova_compile_many_v2(inputs,PATHS_N,&art)||!nova_host_map(&art,&image))return 2;
  const char *files[]={"examples/ntasm-v0/c-bootstrap/mutable-data.ntasm","examples/ntasm-v0/c-bootstrap-controlflow/comparison-condition-refused.ntasm","examples/ntasm-v0/corpus-e2e/memory-space-user-data.ntasm","examples/ntasm-v0/corpus-e2e/register-width-binding.ntasm"};
  Run r;run_init(&r);
  for(unsigned i=0;i<sizeof files/sizeof *files;i++){
    size_t n;char *src=loadf(files[i],&n);if(!src){fprintf(stderr,"FAIL absent %s\n",files[i]);failures++;continue;}
    run(&image,src,n,0,0,&r);uint64_t bad=r.node;
    printf("MISSING_CASE %s code=%llu runtime=%llu node=%llu\n",files[i],(unsigned long long)r.returned,(unsigned long long)r.runtime,(unsigned long long)bad);
    CHECK(r.returned==0&&r.runtime==0,"valid source lowers to verified MIR");
    if(r.returned||r.runtime){
      run(&image,src,n,2,0,&r);run(&image,src,n,4,0,&r);
      if(r.returned==0&&bad>0&&bad<=r.image[3]){uint64_t at=10+(bad-1)*r.image[5];printf("BAD_MIR");for(uint64_t k=0;k<r.image[5];k++)printf(" %llu",(unsigned long long)r.image[at+k]);puts("");}
      else if(bad>0&&bad<=r.words[3]){uint64_t at=8+(bad-1)*16;printf("BAD_NTIR");for(unsigned k=0;k<16;k++)printf(" %llu",(unsigned long long)r.words[at+k]);puts("");}
    }
    if(i==3 && r.returned==0 && r.runtime==0) {
      const uint64_t expected_family[]={9,8,2,3};unsigned seen=0;uint64_t first_param=0;
      for(uint64_t id=1;id<=r.image[3];id++) {
        uint64_t at=10+(id-1)*r.image[5];
        if(r.image[at]==2054) {
          CHECK(seen<4 && r.image[at+15]==expected_family[seen], "explicit parameter register family survives in MIR");
          if(!first_param) { first_param=at; }
          seen++;
        }
      }
      CHECK(seen==4,"all four explicit parameter bindings are measured");
      if(first_param) {
        uint64_t saved=r.image[first_param+15];r.image[first_param+15]=17;
        run(&image,src,n,5,0,&r);CHECK(r.returned==942&&r.runtime==0,"invalid physical register family is rejected");
        r.image[first_param+15]=saved;
        uint64_t major=r.image[1],minor=r.image[2];
        CHECK(major==1&&minor==3,"typed indirect calls extend the published MIR/1.3 format");
        r.image[1]=0;r.image[2]=3;
        run(&image,src,n,5,0,&r);CHECK(r.returned==930&&r.runtime==0,"old MIR version cannot silently lose explicit ABI metadata");
        r.image[1]=major;r.image[2]=minor;run(&image,src,n,5,0,&r);CHECK(r.returned==0&&r.runtime==0,"restored MIR ABI metadata verifies");
      }
    }
    free(src);
  }
  run_free(&r);nova_host_unmap(&image);nt_artifact_free(&art);for(unsigned i=0;i<PATHS_N;i++)free(sources[i]);
  printf("NTASM_NOVA_MACHINE_MISSING checks=%u failures=%u\n",checks,failures);return failures?1:0;
}
