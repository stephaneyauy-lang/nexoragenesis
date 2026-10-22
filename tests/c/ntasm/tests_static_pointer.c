#include "../../../compiler/c/ntasm/frontend/ntasm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks,failures;
#define CHECK(c,m) do{++checks;if(!(c)){++failures;fprintf(stderr,"FAIL: %s\n",m);}}while(0)
static uint64_t u64(const uint8_t *p){uint64_t n=0;for(unsigned j=0;j<8;j++)n|=(uint64_t)p[j]<<(8*j);return n;}


/* The two sides of the pair below differ by ONE token, at ONE site. */
#define SP_HEAD \
  "module static_pointer\ntarget x86_64-nexora-uefi\nsection .data {\n" \
  "data answer:u64=42\ndata saved:ptr<user,u64> = intrinsic address_of("
#define SP_TAIL \
  ")\n}\nsection .text {\nexport fn main()->u64\neffects {}\nclobbers {} {\nreturn 42\n}\n}\n"
/* ===========================================================================
 * THE REFUSAL/CONTROL PAIR, and it is here because every fixture this file
 * held was VALID. `intrinsic address_of(answer)` names a real .data symbol,
 * so the pointer-space guard -- "address_of requires a static data symbol" --
 * was named by the tree and never fed. A fabricated preferred address
 * reproduces 0x140003000 and a relocation count of 1 identically, so nothing
 * here could tell a running guard from a value that merely looks right.
 *
 * THE PAIR IS ONE TOKEN: `answer` -> `main`. `main` is a real, declared
 * symbol in the same module -- it is not an invented name -- but it lives in
 * .text, and address_of is defined over STATIC DATA. So the two sides differ
 * by one identifier and the difference is exactly the one the guard names.
 *
 * MEASURED, not transcribed: nt_compile answers NTF_E_NAME 301, "address_of
 * requires a static data symbol", and produces no text. Pinned from a run.
 *
 * THE POISON: the artifact is filled with 0xcc before the call and must come
 * back 0xcc. A refusal that still emitted a section, a relocation, or a data
 * image would be caught; `ok == 0` alone would not catch it.
 * ======================================================================== */
/* THE POISON, and here it is stated as ABSENCE rather than as 0xcc survival,
 * for a measured reason: nt_compile memsets its own output struct before it
 * fails (compiler/c/ntasm/frontend/ntasm.c, the same discipline nt_object_read
 * documents -- "Failed reads remain empty"). So a byte-for-byte poison
 * assertion over the struct would be asserting that the compiler does NOT
 * clear its output, which is a claim about a different thing and would be a
 * wrong pin rather than a strict one.
 *
 * What the guard must guarantee is that nothing was PRODUCED. That is stated
 * exactly: no section carries bytes, and no relocation table exists. A
 * fabricated answer -- a compiler that returned an error while still
 * materialising 0x140003000 and a DIR64 site -- passes `ok == 0` and fails
 * these. The control arm is what makes it non-vacuous: it shows the accepted
 * side of the same one-token difference really does produce both. */
static void pair_refuses_address_of_function(void){
  /* THE CONTROL: the fixture this file already had, unchanged. It must be
   * accepted, and it must really materialize an address. */
  {
    const char *source=SP_HEAD "answer" SP_TAIL;
    NtArtifact a={0};
    int ok=nt_compile(source,strlen(source),&a);
    CHECK(ok,"SP control: address_of a real .data symbol is accepted");
    if(ok){
      CHECK(a.base_relocation_count==1,"SP control: one DIR64 site is produced");
      CHECK(a.data.size==16&&a.data.bytes&&u64(a.data.bytes+8)==UINT64_C(0x140003000),"SP control: the preferred address is really materialized");
      nt_artifact_free(&a);
    } else fprintf(stderr,"SP_CONTROL E%u %s\n",a.error.code,a.error.message);
  }
  /* THE REFUSAL: one token. Exact code, and no artifact behind it. */
  {
    const char *source=SP_HEAD "main" SP_TAIL;
    NtArtifact a; memset(&a,0xcc,sizeof a);
    int ok=nt_compile(source,strlen(source),&a);
    CHECK(!ok,"SP refusal: address_of a .text function is refused, one token from the accepted control");
    if(!ok){
      CHECK(a.error.code==301,"SP refusal: the exact error code is NTF_E_NAME 301");
      fprintf(stderr,"SP_PAIR_REFUSAL code=%u %s\n",a.error.code,a.error.message);
    }
    CHECK(!a.text.bytes&&!a.pe.bytes&&!a.rdata.bytes&&!a.data.bytes,
          "SP refusal: no section carries bytes, so no artifact was fabricated behind the refusal");
    CHECK(a.base_relocation_count==0&&!a.base_relocations,
          "SP refusal: no relocation table exists, so the DIR64 site was not emitted either");
    nt_artifact_free(&a);
  }
}

int main(void){
 const char *source="module static_pointer\ntarget x86_64-nexora-uefi\nsection .data {\ndata answer:u64=42\ndata saved:ptr<user,u64> = intrinsic address_of(answer)\n}\nsection .text {\nexport fn main()->u64\neffects {}\nclobbers {} {\nreturn 42\n}\n}\n";
 NtArtifact a={0};int ok=nt_compile(source,strlen(source),&a);CHECK(ok,"compile real typed static address source");
 if(ok){CHECK(a.base_relocation_count==1&&a.base_relocations[0].section==3&&a.base_relocations[0].offset==8,"direct compiler retains data DIR64 site");CHECK(a.data.size==16&&u64(a.data.bytes+8)==UINT64_C(0x140003000),"direct compiler materializes preferred address before PE writer");CHECK(nt_make_pe(&a),"direct typed address produces PE");}
 else fprintf(stderr,"E%u %s\n",a.error.code,a.error.message);
 nt_artifact_free(&a);
 pair_refuses_address_of_function();
 printf("NTASM_STATIC_POINTER_TESTS checks=%u failures=%u pair=address-of-function\n",checks,failures);return failures?1:0;
}