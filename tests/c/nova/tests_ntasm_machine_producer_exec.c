#define _GNU_SOURCE
#include <unistd.h>
#include <signal.h>
static pid_t bounded_fork(void) { pid_t p=fork(); if(p==0)alarm(5);return p; }
#define fork bounded_fork
#define main existing_pe_execution_gate_main
#include "tests_ntasm_pe_exec.c"
#undef main
#undef fork
#include "../../../compiler/c/nova/backend/machine_driver.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/ntasm/formats/object.h"
#include <string.h>
typedef struct {const char *path,*name;uint64_t want;} Program;
#define EX "examples/ntasm-v0/"
static const Program programs[]={
 {EX "a4-contracts/constant-name.ntasm","a4-constant-name",42},
 {EX "a4-contracts/catalog-nova.ntasm","a4-catalog-nova",42},
 {EX "a4-contracts/catalog.ntasm","a4-contract-catalog",42},
 {EX "a4-contracts/constant-fold.ntasm","a4-contract-constant-fold",42},
 {EX "a4-contracts/sort-dedup.ntasm","a4-contract-sort-dedup",42},

 {EX "abi-efi/go-efi-nested.ntasm","go-efi-nested",49},
 {EX "abi-efi/go-efi-weighted-stack.ntasm","go-efi-weighted-stack",97},
 {EX "abi-efi/go-efi-two-calls.ntasm","go-efi-two-calls",121},

 {EX "abi-efi/requires-feature.ntasm","requires-feature",42},
 {EX "abi-efi/pointer-return.ntasm","efi-pointer-return",42},
 {EX "a4-clobbers/rip-call.ntasm","clobbers-rip",42},
 {EX "a4-clobbers/gsbase-call.ntasm","clobbers-gsbase",42},
 {EX "a4-clobbers/fsbase-call.ntasm","clobbers-fsbase",42},

 {EX "abi-efi/default-efi-local-nx64.ntasm","mixed-efi-nx64",42},
 {EX "abi-efi/default-nx64-local-efi.ntasm","mixed-nx64-efi",42},

 {EX "abi-efi/call0.ntasm","efi-call0",42},
 {EX "abi-efi/call5.ntasm","efi-call5",6},
 {EX "abi-efi/call15.ntasm","efi-call15",21},
 {EX "abi-efi/call64.ntasm","efi-call64",85},

 {EX "c-bootstrap/return42.ntasm","return42",42},
 {EX "c-bootstrap/return43.ntasm","return43",43},
 {EX "c-bootstrap/returnmax.ntasm","returnmax",UINT64_MAX},
 {EX "c-bootstrap/helper-first.ntasm","helper-first",42},
 {EX "c-bootstrap/static-data.ntasm","static-data",42},
 {EX "c-bootstrap/mutable-data.ntasm","mutable-data",42},
 {EX "c-bootstrap/comptime-macro.ntasm","comptime-macro",42},
 {EX "c-bootstrap/call-private-stmt.ntasm","call-private",21},
 {EX "c-bootstrap-controlflow/branching-entry.ntasm","branching-entry",42},
 {EX "c-bootstrap-controlflow/comparison-condition-refused.ntasm","comparison",42},
 {EX "c-bootstrap-controlflow/branching-runtime.ntasm","branching-runtime",43},
 {EX "frame-gate-fixtures/frame-omission.ntasm","frame-omission",42},
 {EX "frame-gate-fixtures/shortcut-control.ntasm","shortcut-control",42},
 {EX "corpus-e2e/features-declared.ntasm","features",17},
 {EX "corpus-e2e/register-width-binding.ntasm","register-bindings",42},
 {EX "corpus-e2e/memory-space-user-data.ntasm","memory-spaces",42}
};
static void execute_output(const char *name,NtBuffer *out,uint64_t want) {
 uint64_t got=0;char why[200]={0};int rc=run_child(out->bytes,out->size,&got,why,sizeof why);
 CHECK(rc==0&&got==want,"%s execution rc=%d got=%" PRIu64 " want=%" PRIu64 " %s",name,rc,got,want,why);
 printf("MIR_EXEC name=%s bytes=%zu rc=%d got=%" PRIu64 " want=%" PRIu64 "\n",name,out->size,rc,got,want);
}
static void host_capacity_checks(void) {
    unsigned checks_before=checks, failures_before=failures;
#define HOST_CHECK(x) CHECK((x), "host mapping capacity: %s", #x)
    NtArtifact a={0};NovaHostImage mapped={0};
    a.text.size=16u*1024u*1024u+1;
    a.text.bytes=calloc(NOVA_HOST_TEXT_LIMIT,1);
    HOST_CHECK(a.text.bytes!=NULL);
    if(!a.text.bytes)return;
    a.text.bytes[0]=0xc3; /* Only mapping is tested; these bytes are never executed. */
    HOST_CHECK(nova_host_map(&a,&mapped));
    HOST_CHECK(mapped.memory!=NULL&&mapped.entry!=NULL);
    nova_host_unmap(&mapped);
    a.text.size=NOVA_HOST_TEXT_LIMIT;
    HOST_CHECK(nova_host_map(&a,&mapped));
    nova_host_unmap(&mapped);
    a.text.size=(size_t)NOVA_HOST_TEXT_LIMIT+1;
    HOST_CHECK(!nova_host_map(&a,&mapped));
    HOST_CHECK(mapped.memory==NULL);
    a.text.size=1;a.entry=1;
    HOST_CHECK(!nova_host_map(&a,&mapped));
    a.entry=0;a.rdata.size=16u*1024u*1024u+1;
    HOST_CHECK(!nova_host_map(&a,&mapped));
    a.rdata.size=0;a.data.size=16u*1024u*1024u+1;
    HOST_CHECK(!nova_host_map(&a,&mapped));
    free(a.text.bytes);
    printf("NTASM_NOVA_HOST_CAPACITY checks=%u failures=%u text_limit=%u\n",checks-checks_before,failures-failures_before,NOVA_HOST_TEXT_LIMIT);
}

#undef HOST_CHECK

/* C(source originale) -> NXO, via the C bootstrap object entry. */
static int compile_c_object(const char *path, NtObject *out, NtDiagnostic *err) {
  size_t n = 0;
  uint8_t *src = readall(path, &n);
  if (!src)
    return 0;
  NtFInput input = {0};
  input.name = path;
  input.text = (const char *)src;
  input.length = n;
  int ok = nt_object_compile(&input, 1, out, err);
  free(src);
  return ok;
}

/* One fixture: compare C and Nova NXO contracts for leaf/main by exact
 * qualified name. Nova(source originale) currently refuses (983), so the
 * accept CHECK here is RED on purpose and the refusal is printed, never
 * skipped. */
static void contract_case(NtMachineImage *producer, const char *path,
                          const char *leaf, const char *main) {
  cases++;
  NtDiagnostic err = {0};
  NtObject c = {0};
  int c_ok = compile_c_object(path, &c, &err);
  CHECK(c_ok, "C producer must accept %s: E%u %s", path, err.code, err.message);

  size_t n = 0;
  uint8_t *src = readall(path, &n);
  NtBuffer out = {0};
  NtMachineReport rep = {0};
  int nova_ok = src && nt_machine_object(producer, (char *)src, n, &out, &rep);
  CHECK(src != NULL, "source exists: %s", path);
  free(src);
  CHECK(nova_ok && out.size,
        "Nova producer must accept %s: returned=%" PRIu64 " runtime=%" PRIu64
        " stage=%" PRIu64 " code=%" PRIu64,
        path, rep.returned, rep.runtime, rep.stage, rep.code);

  NtObject nova = {0};
  if (nova_ok && out.size)
    CHECK(nt_object_read(out.bytes, out.size, &nova, &err),
          "Nova NXO must read: E%u %s", err.code, err.message);
  free(out.bytes);

  if (!c_ok || !nova_ok || !nova.symbol_count) {
    nt_object_free(&c);
    nt_object_free(&nova);
    return;
  }

  const char *names[2] = {leaf, main};
  for (unsigned i = 0; i < 2; i++) {
    const char *nm = names[i];
    size_t c_hits = 0, n_hits = 0;
    const NtObjectSymbol *cs = NULL, *ns = NULL;
    for (size_t k = 0; k < c.symbol_count; k++)
      if (c.symbols[k].name && !strcmp(c.symbols[k].name, nm)) {
        c_hits++; cs = &c.symbols[k];
      }
    for (size_t k = 0; k < nova.symbol_count; k++)
      if (nova.symbols[k].name && !strcmp(nova.symbols[k].name, nm)) {
        n_hits++; ns = &nova.symbols[k];
      }
    CHECK(c_hits == 1, "%s: C has %zu definitions of %s", path, c_hits, nm);
    CHECK(n_hits == 1, "%s: Nova has %zu definitions of %s", path, n_hits, nm);
    if (c_hits != 1 || n_hits != 1)
      continue;
    CHECK(cs->contract && ns->contract, "%s: %s has a non-null contract", path, nm);
    CHECK(cs->contract && ns->contract && !strcmp(cs->contract, ns->contract),
          "%s: %s contract C<Nova: C=[%s] Nova=[%s]", path, nm,
          cs->contract ? cs->contract : "(null)",
          ns->contract ? ns->contract : "(null)");
    CHECK(cs->flags == ns->flags, "%s: %s flags C=%u Nova=%u", path, nm,
          cs->flags, ns->flags);
    CHECK((cs->flags & NT_OBJECT_FUNCTION) && (ns->flags & NT_OBJECT_FUNCTION),
          "%s: %s is a function on both sides", path, nm);
    if (!strcmp(nm, main))
      CHECK((cs->flags & NT_OBJECT_EXPORT) && (ns->flags & NT_OBJECT_EXPORT),
            "%s: %s exported on both sides", path, nm);
    else
      CHECK(!(cs->flags & NT_OBJECT_EXPORT) && !(ns->flags & NT_OBJECT_EXPORT),
            "%s: %s private on both sides", path, nm);
    printf("NTASM_NOVA_NXO_CONTRACT name=%s c_flags=%u nova_flags=%u c=[%s]\n",
           nm, cs->flags, ns->flags, cs->contract ? cs->contract : "(null)");
  }
  nt_object_free(&c);
  nt_object_free(&nova);
}

/* The six additional v0 predicates are implemented in Nova, not in the C
 * reference. Pin that refusal, then check the actual Nova contract against
 * an independently written canonical expectation. Do not call it C parity. */
static void full_catalog_contract(NtMachineImage *producer) {
 const char *path=EX "a4-contracts/catalog-nova.ntasm";
 const char *expected="fn;target=x86_64-nexora-uefi;abi=nx64-abi-v0;features=9;section=.text;ret=u64;params=(0:ptr<1,u64>@7/64/0);effects=0/0/0;clobbers=0000000000000000;requires={pred(canonical,param(0)),pred(feature),pred(interrupts_enabled),pred(mapping_present,param(0)),pred(msr_initialized,lit(u64,0000000000000001,0)),pred(non_null,param(0)),pred(stack_aligned,lit(u64,0000000000000010,0)),pred(stack_in,name(kernel)),pred(valid_user_return,param(0),param(0))};ensures={pred(canonical,param(0)),pred(interrupts_enabled)}";
 NtObject ref={0};NtDiagnostic d={0};int cok=compile_c_object(path,&ref,&d);
 CHECK(!cok && d.code==600,"C reference explicitly lacks full predicate catalogue code=%u",d.code);nt_object_free(&ref);
 size_t n=0;uint8_t *src=readall(path,&n);NtBuffer bytes={0};NtMachineReport r={0};NtObject o={0};cases++;
 CHECK(src!=NULL,"full catalogue source");int ok=src&&nt_machine_object(producer,(char*)src,n,&bytes,&r);
 CHECK(ok && !r.runtime,"Nova full catalogue NXO code=%llu runtime=%llu",(unsigned long long)r.code,(unsigned long long)r.runtime);
 if(ok){CHECK(nt_object_read(bytes.bytes,bytes.size,&o,&d),"full catalogue NXO decodes");unsigned found=0;
  for(size_t i=0;i<o.symbol_count;i++)if(!strcmp(o.symbols[i].name,"a4.catalog.leaf")){found++;CHECK(o.symbols[i].contract && !strcmp(o.symbols[i].contract,expected),"full catalogue exact contract got=[%s]",o.symbols[i].contract?o.symbols[i].contract:"null");}
  CHECK(found==1,"full catalogue leaf exactly once");}
 nt_object_free(&o);free(bytes.bytes);free(src);
}
int main(void) {
 host_capacity_checks();
 setvbuf(stdout,NULL,_IONBF,0);NtDiagnostic err={0};NtMachineImage *producer=nt_machine_open(".",&err);
 CHECK(producer!=NULL,"MIR producer compile/map: E%u %s",err.code,err.message);
 if(!producer){printf("NTASM_NOVA_MACHINE_PRODUCER_EXEC checks=%u failures=%u cases=0\n",checks,failures);return 1;}
 unsigned emitted=0;
 for(unsigned i=0;i<sizeof programs/sizeof *programs;i++){
  size_t n=0;uint8_t *source=readall(programs[i].path,&n);NtBuffer out={0};NtMachineReport r={0};cases++;
  CHECK(source!=NULL,"source exists: %s",programs[i].path);if(!source)continue;
  int ok=nt_machine_pe(producer,(char*)source,n,&out,&r);
  CHECK(ok&&out.size&&r.runtime==0,"%s must produce PE: returned=%" PRIu64 " runtime=%" PRIu64 " stage=%" PRIu64 " code=%" PRIu64,programs[i].name,r.returned,r.runtime,r.stage,r.code);
  printf("MIR_BUILD name=%s ok=%d size=%zu returned=%" PRIu64 " runtime=%" PRIu64 " stage=%" PRIu64 "\n",programs[i].name,ok,out.size,r.returned,r.runtime,r.stage);
  if(r.runtime) printf("MIR_RUNTIME name=%s source=%" PRIu64 " offset=%" PRIu64 " error=%" PRIu64 "\n",programs[i].name,r.runtime_source,r.runtime_offset,r.runtime);
  if(ok&&out.size&&r.runtime==0){emitted++;execute_output(programs[i].name,&out,programs[i].want);}free(out.bytes);free(source);
 }
 /* A genuine two-module input: explicit caller expression preserves macro hygiene. */
 const char *multi[]={EX "common-pipeline/multi-explicit-app.ntasm",EX "c-bootstrap-multi/math.ntasm"};
 NtBuffer objects[2]={{0}},linked={0};NtMachineReport report={0};int ready=1;
 for(unsigned i=0;i<2;i++){size_t n=0;uint8_t *source=readall(multi[i],&n);int ok=source&&nt_machine_object(producer,(char*)source,n,objects+i,&report);CHECK(ok,"multi object %u returned=%" PRIu64 " runtime=%" PRIu64,i,report.returned,report.runtime);ready=ready&&ok;free(source);}
 if(ready){int ok=nt_machine_link(producer,objects,2,&linked,&report);CHECK(ok,"two-module MIR objects link: code=%" PRIu64,report.code);if(ok){emitted++;execute_output("multi-explicit",&linked,42);}}
 free(objects[0].bytes);free(objects[1].bytes);free(linked.bytes);cases++;
contract_case(producer,EX "abi-efi/requires-feature.ntasm","contract.feature.leaf","contract.feature.main");
 contract_case(producer,EX "abi-efi/pointer-return.ntasm","efi.pointer.leaf","efi.pointer.main");

 contract_case(producer,EX "a4-contracts/catalog.ntasm","a4.catalog.leaf","a4.catalog.main");
 contract_case(producer,EX "a4-contracts/constant-fold.ntasm","a4.constant_fold.leaf","a4.constant_fold.main");
 contract_case(producer,EX "a4-contracts/sort-dedup.ntasm","a4.sort_dedup.leaf","a4.sort_dedup.main");
 contract_case(producer,EX "a4-contracts/constant-name.ntasm","a4.constant_name.leaf","a4.constant_name.main");
 contract_case(producer,EX "a4-clobbers/rip-call.ntasm","clobber.rip.leaf","clobber.rip.main");
 contract_case(producer,EX "a4-clobbers/gsbase-call.ntasm","clobber.gsbase.leaf","clobber.gsbase.main");
 contract_case(producer,EX "a4-clobbers/fsbase-call.ntasm","clobber.fsbase.leaf","clobber.fsbase.main");
 full_catalog_contract(producer);
 nt_machine_close(producer);printf("NTASM_NOVA_MACHINE_PRODUCER_EXEC checks=%u failures=%u cases=%u emitted=%u\n",checks,failures,cases,emitted);return failures?1:0;
}
