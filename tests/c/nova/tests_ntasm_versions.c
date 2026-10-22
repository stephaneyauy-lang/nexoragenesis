#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks,failures,cases;static const uint64_t guard=UINT64_C(0xcccccccccccccccc);
#define CHECK(c,m) do{checks++;if(!(c)){failures++;fprintf(stderr,"FAIL %s\n",m);}}while(0)
static char*loadf(const char*p,size_t*n){FILE*f=fopen(p,"rb");if(!f)return NULL;fseek(f,0,SEEK_END);long z=ftell(f);fseek(f,0,SEEK_SET);char*b=z>=0?malloc((size_t)z+1):NULL;if(!b||fread(b,1,(size_t)z,f)!=(size_t)z){free(b);fclose(f);return NULL;}fclose(f);b[z]=0;*n=(size_t)z;return b;}
typedef struct{uint64_t returned,runtime,out[4];}Run;static Run run(const NovaHostImage*i,const char*s,uint64_t words){Run r={.out={guard,guard,guard,guard}};NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"context init");uint64_t sh=nova_borrow_v2(&c,(void*)s,strlen(s),0),oh=nova_borrow_v2(&c,r.out,words*8,1);uint64_t a[]={sh,strlen(s),oh,words};r.returned=i->entry(&c,a,4);r.runtime=c.error;CHECK(nova_context_destroy_v2(&c),"context cleanup");return r;}
static void ok(const NovaHostImage*i,const char*n,const char*s,uint64_t b,uint64_t e,uint64_t m){Run r=run(i,s,4);cases++;checks++;if(r.returned||r.runtime||r.out[0]!=b||r.out[1]!=e||r.out[2]!=m||r.out[3]){failures++;fprintf(stderr,"FAIL ok %s ret=%llu out=%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2]);}}
static void err(const NovaHostImage*i,const char*n,const char*s,uint64_t code,uint64_t a,uint64_t b){Run r=run(i,s,4);cases++;checks++;if(r.returned!=code||r.runtime||r.out[0]==guard||r.out[1]==guard||r.out[2]!=a||r.out[3]!=b){failures++;fprintf(stderr,"FAIL err %s ret=%llu out=%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
static void bad(const NovaHostImage*i,const char*n,const char*s,uint64_t words){Run r=run(i,s,words);cases++;checks++;if(r.returned!=800||r.runtime||r.out[0]!=guard||r.out[1]!=guard){failures++;fprintf(stderr,"FAIL invalid %s\n",n);}}
#define HEAD "module m\ntarget x86_64-nexora-none\n"
#define FULL "versions {\nntir 0.1\nmachine_ir 0.1\nsections 0.1\nsymbols 0.1\nrelocations 0.1\nnxo 0.1\n}\n"
/* ==========================================================================
   THE machine_ir DOMAIN BIT -- THE CONFRONT, AND WHAT EACH SIDE PUBLISHES.

   MEASURED FIRST, because the shape of the answer decided the shape of the
   check.  A throwaway probe ran BOTH entries and printed every published word:

     versions_entry.main("...versions {\nntir 0.1\nmachine_ir 0.1\n...all six...\n}")
         -> ret 0, out = 1, 6, 63, 0
     versions_entry.main("...versions {\nmachine_ir 0.1\n}\n")
         -> ret 349, out = 3, 1, 2, 0
     versions_entry.main("...versions {\nsections 0.1\n}\n")
         -> ret 349, out = 3, 1, 4, 0
     machine_ir_entry mode 7 -> report[4] = 2

   THE FIRST LINE IS WHY THIS GATE IS NOT WRITTEN THE OBVIOUS WAY.  On the
   all-six block out[2] is 63 -- the OR of every domain bit -- so comparing
   it with report[4]=2 would have confronted a SIX-BIT MASK with a SINGLE BIT,
   which is not a comparison of two readings of one fact but the arithmetic
   fact that 63 and 2 are different numbers.  That check would be red on a
   tree where both modules are right, and green only if someone made them
   agree by hand.  So the source side is read on a block that names ONE
   domain, where the mask versions.nova published IS that domain's bit, and
   that shape is not an invention here: the `incomplete` case above already
   reads out[2] as the mask on exactly this 349 path.

   READ THE RIGHT FIELD.  out[2] does not mean one thing.  On code 0 and on
   code 349 it is the mask; on code 348 it is the MAJOR version.  Every read
   below therefore asserts the return code FIRST and refuses on anything but
   349, because a gate that reads a word it has not established the meaning
   of is reading a number that merely resembles the right one.  The sentinels
   do the rest: `guard` is what an entry that refused before writing leaves
   behind, and an absent value is not a zero.

   WHY THE TWO SIDES ARE NOT THE SAME THING.  versions.nova imports
   ntasm_ast and nothing else; machine_ir.nova imports ntir and
   register_widths and nothing else.  Neither can see the other's constant.
   The left number is produced by `domain()`, which compares the SOURCE BYTES
   of the name against six literals and returns a bit -- it is a function of
   the text fed in.  The right number is the body of DOMAIN_BIT(), a literal
   `return 2` -- it is a function of the module and of no input at all.  Both
   red proofs below move exactly one of them and are asserted to leave the
   other where it was, which is the difference between a confront and a side
   compared with itself.

   SECOND IMAGE, NOT SECOND GATE.  machine-ir-entry.nova needs eleven modules
   and versions-entry.nova needs five, so the eleven are compiled and mapped
   as a SECOND ARTIFACT inside this same main(), in this same process, in
   this same binary.  Its list is a hand-maintained copy of a closure the
   tree derives, which is how this tree has been bitten before, so it is
   asked ng_parity_closure_is BEFORE the compile rather than being left to
   stand for whatever E302 says three hundred lines later.
   ========================================================================== */
#define MIR_REPORT 256
#define MIR_OUT 4096
#define MIR_TEXT 4096
static const char*const MIR_PATHS[]={"tests/nova/tests/machine-ir-entry.nova","compiler/nova/ir/machine_ir.nova","compiler/nova/formats/ntir/ntir.nova","compiler/nova/ir/ir_image.nova","compiler/nova/formats/pe/pe.nova","compiler/nova/frontend/parser.nova","compiler/nova/frontend/lexer.nova","compiler/nova/frontend/ast.nova","compiler/nova/analysis/types/register_widths.nova","compiler/nova/analysis/types/pointer_spaces.nova","compiler/nova/frontend/versions.nova"};
#define MIR_N ((unsigned)(sizeof MIR_PATHS/sizeof MIR_PATHS[0]))
/* WHY NOT ng_parity_closure_is, MEASURED AND NOT GUESSED.  It was called on
   this list first and it refused, naming the whole failure:

     "compiler/nova/ir/ir_image.nova imports ntasm_pe and no file in the
      tree carries it"

   and it is right.  ir_image.nova imports `ntasm_pe`, the module declared at
   the top of pe.nova, and the shared resolver maps a module name to a file
   through ng_parity_alias, a table of pairs that carries ntasm_ast, ntasm_refs,
   ntasm_ntir and five others but NOT ntasm_pe.  So that resolver cannot close
   THIS entry however correct the list below is: nothing in this file can make
   its walk succeed, and the walk would then be a permanently-red check over a
   module list that is in fact right.  It is not this lot's business to widen
   that table -- a shared header three other gates read is not one file's to
   change -- so the guard below derives the same answer from the tree itself:
   an import names a MODULE, and the file that carries a module is the one
   whose first line declares it.  That is a fact about the tree, read at run
   time, and it cannot drift the way a hand-written pair table drifts. */
/* A module declaration is the first statement, not the first physical
   line. Comments can be longer than 128 bytes; inspect the whole source. */
static const char *mir_skip_space(const char *p) {
  for (;;) {
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') ++p;
    if (p[0] != '/' || p[1] != '/') return p;
    while (*p && *p != '\n') ++p;
  }
}
static int mir_declares(const char *source, const char *name) {
  const char *p = mir_skip_space(source);
  if (strncmp(p, "module", 6) ||
      (p[6] != ' ' && p[6] != '\t' && p[6] != '\r' && p[6] != '\n')) return 0;
  p = mir_skip_space(p + 6);
  size_t len = strlen(name);
  if (strncmp(p, name, len)) return 0;
  return *mir_skip_space(p + len) == ';';
}
static int mir_carries(const char *dir, const char *name, char *out, size_t n) {
  DIR *d = opendir(dir);
  struct dirent *e;
  char path[320];
  int found = 0;
  if (!d) return 0;
  while (!found && (e = readdir(d)) != NULL) {
    size_t len = strlen(e->d_name), size = 0;
    if (len < 5 || strcmp(e->d_name + len - 5, ".nova")) continue;
    if (snprintf(path, sizeof path, "%s/%s", dir, e->d_name) >= (int)sizeof path) continue;
    char *source = loadf(path, &size);
    if (!source) continue;
    if (mir_declares(source, name)) {
      if (snprintf(out, n, "%s", path) < (int)n) found = 1;
    }
    free(source);
  }
  closedir(d);
  return found;
}
static void mir_declaration_reader_cases(void) {
  CHECK(mir_declares("// comment; module fake;\n module machine_ir;import ntir;", "machine_ir"), "module after comment and indentation");
  CHECK(mir_declares("module\n machine_ir // tail\n ;", "machine_ir"), "module whitespace and comment");
  CHECK(!mir_declares("// module machine_ir;\nmodule other;", "machine_ir"), "comment is not a declaration");
  CHECK(!mir_declares("module machine_ir_suffix;", "machine_ir"), "module prefix is not a match");
  CHECK(!mir_declares("module machine_ir", "machine_ir"), "unterminated declaration rejected");
  CHECK(!mir_declares("import machine_ir; module machine_ir;", "machine_ir"), "declaration must precede imports");
}
/* The closure of MIR_PATHS[0], walked from the module declarations, and the
   question the splice gate's own comment says this list needs asked BEFORE the
   compile: is the hand-maintained row set the whole closure?  Both directions
   -- a row the walk never reaches, and a module the walk reaches that no row
   carries -- are named, because a list that is only checked in one direction
   is a list that can quietly grow stale. */
static int mir_closure_is(char *why, size_t whylen) {
  const char *seen[64];
  char store[64][320];
  size_t n = 0, i;
  snprintf(store[0], sizeof store[0], "%s", MIR_PATHS[0]);
  seen[0] = store[0];
  n = 1;
  for (i = 0; i < n; i++) {
    size_t len = 0;
    char *text = loadf(seen[i], &len);
    const char *p;
    if (!text) { snprintf(why, whylen, "the closure reached %s and it cannot be read", seen[i]); return 0; }
    for (p = text; (p = strstr(p, "import ")) != NULL; p += 7) {
      char name[64], next[320];
      size_t k, w = 0, dup = 0;
      const char *q = p + 7;
      /* An import is the word `import`, a module name, and a `;`.  All three
         are required, and the `;` is what makes this a STATEMENT scan rather
         than a substring one: ntir.nova carries a prose comment reading "A
         function and an import both close with a return type", and a scanner
         that accepted the name up to the end of the line read `both` as a
         module and reported an import no file declares.  Requiring the
         semicolon skips that sentence and accepts every real import, since
         every import in this tree ends in one. */
      while (*q && *q != ';' && w + 1 < sizeof name) {
        if (*q != ' ' && *q != '\t' && *q != '\n' && *q != '\r') name[w++] = *q;
        q++;
      }
      name[w] = 0;
      if (!name[0] || *q != ';') continue;
      if (!mir_carries("compiler/nova", name, next, sizeof next)) {
        snprintf(why, whylen, "%s imports %s and no file declares that module", seen[i], name);
        free(text);
        return 0;
      }
      for (k = 0; k < n; k++) if (strcmp(seen[k], next) == 0) { dup = 1; break; }
      if (dup) continue;
      if (n >= 64) { snprintf(why, whylen, "the closure is larger than the room this file counts"); free(text); return 0; }
      memcpy(store[n], next, strlen(next) + 1);
      seen[n] = store[n];
      n++;
    }
    free(text);
  }
  for (i = 0; i < MIR_N; i++) {
    size_t k;
    int in = 0;
    for (k = 0; k < n; k++) if (strcmp(seen[k], MIR_PATHS[i]) == 0) { in = 1; break; }
    if (!in) { snprintf(why, whylen, "the list carries %s and the closure of %s never reaches it", MIR_PATHS[i], MIR_PATHS[0]); return 0; }
  }
  for (i = 0; i < n; i++) {
    size_t k;
    int in = 0;
    for (k = 0; k < MIR_N; k++) if (strcmp(MIR_PATHS[k], seen[i]) == 0) { in = 1; break; }
    if (!in) { snprintf(why, whylen, "the closure reaches %s and the list does not carry it", seen[i]); return 0; }
  }
  return 1;
}
static uint64_t mir_out[MIR_OUT],mir_text[MIR_TEXT/8],mir_length[4],mir_report[MIR_REPORT];
/* The one number machine_ir.nova publishes about its own versions domain,
   read back through the entry's mode 7 and not written down in this file.
   The report is filled with the guard pattern first, so a mode 7 that wrote
   nothing is told apart from one that wrote zero. */
static uint64_t mir_bit(const NovaHostImage*i){memset(mir_report,0xcc,sizeof mir_report);memset(mir_out,0,sizeof mir_out);memset(mir_text,0,sizeof mir_text);memset(mir_length,0,sizeof mir_length);NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"machine_ir context init");uint64_t sh=nova_borrow_v2(&c,(void*)"\n",1,0);uint64_t wh=nova_borrow_v2(&c,mir_out,MIR_OUT*8,1);uint64_t th=nova_borrow_v2(&c,mir_text,MIR_TEXT,1);uint64_t lh=nova_borrow_v2(&c,mir_length,4*8,1);uint64_t rh=nova_borrow_v2(&c,mir_report,MIR_REPORT*8,1);uint64_t args[]={sh,1,7,0,wh,MIR_OUT,MIR_OUT,wh,MIR_OUT,MIR_OUT,th,MIR_TEXT,lh,4,rh,MIR_REPORT};uint64_t ret=i->entry(&c,args,16);uint64_t rt=c.error;CHECK(nova_context_destroy_v2(&c),"machine_ir context cleanup");CHECK(rt==0,"machine_ir mode 7 runs without a runtime error");CHECK(mir_report[4]!=guard,"machine_ir mode 7 writes the domain bit");(void)ret;return mir_report[4];}
int main(void){mir_declaration_reader_cases();const char*paths[]={"tests/nova/tests/versions-entry.nova","compiler/nova/frontend/versions.nova","compiler/nova/frontend/parser.nova","compiler/nova/frontend/ast.nova","compiler/nova/frontend/lexer.nova"};char*sources[5]={0};NtFInput inputs[5];for(unsigned i=0;i<5;i++){size_t n=0;sources[i]=loadf(paths[i],&n);inputs[i]=(NtFInput){paths[i],sources[i],n};}int all=1;for(unsigned i=0;i<5;i++)if(!sources[i])all=0;CHECK(all,"sources load");NtArtifact a={0};int compiled=all&&nova_compile_many_v2(inputs,5,&a);CHECK(compiled,"modules compile");if(!compiled)fprintf(stderr,"E%u %zu:%zu %s\n",a.error.code,a.error.line,a.error.column,a.error.message);NovaHostImage image={0};CHECK(compiled&&nova_host_map(&a,&image),"image maps");if(image.memory){ok(&image,"none",HEAD,0,0,0);ok(&image,"full",HEAD FULL,1,6,63);const char*unknown=HEAD "versions {\nfoo 0.1\n}\n";err(&image,"unknown",unknown,347,1,0);const char*duplicate=HEAD "versions {\nntir 0.1\nntir 0.1\n}\n";err(&image,"duplicate",duplicate,347,2,0);const char*wrong=HEAD "versions {\nntir 1.0\nmachine_ir 0.1\nsections 0.1\nsymbols 0.1\nrelocations 0.1\nnxo 0.1\n}\n";err(&image,"wrong",wrong,348,1,0);const char*incomplete=HEAD "versions {\nntir 0.1\n}\n";err(&image,"incomplete",incomplete,349,1,0);bad(&image,"short",HEAD,3);bad(&image,"invalid","target x86_64-nexora-none\n",4);}char*msources[MIR_N]={0};NtFInput minputs[MIR_N];int mall=1;for(unsigned i=0;i<MIR_N;i++){size_t n=0;msources[i]=loadf(MIR_PATHS[i],&n);if(!msources[i])mall=0;minputs[i]=(NtFInput){MIR_PATHS[i],msources[i],n};}CHECK(mall,"machine_ir sources load");{char why[200];int closed=mir_closure_is(why,sizeof why);checks++;if(!closed){failures++;fprintf(stderr,"FAIL mir-closure: %s\n",why);}fprintf(stderr,"%s the machine_ir module list is the closure of %s: %s\n",closed?"CLOSE-OK":"CLOSE-NO",MIR_PATHS[0],closed?"yes":why);}NtArtifact ma={0};int mcompiled=mall&&nova_compile_many_v2(minputs,MIR_N,&ma);CHECK(mcompiled,"machine_ir modules compile");if(!mcompiled)fprintf(stderr,"M%u %zu:%zu %s\n",ma.error.code,ma.error.line,ma.error.column,ma.error.message);NovaHostImage mimage={0};CHECK(mcompiled&&nova_host_map(&ma,&mimage),"machine_ir image maps");if(image.memory&&mimage.memory){const char*only=HEAD "versions {\nmachine_ir 0.1\n}\n";cases++;Run dom=run(&image,only,4);checks++;if(dom.returned!=349||dom.runtime||dom.out[2]==guard){failures++;fprintf(stderr,"FAIL domain-bit: the source side returned %llu runtime %llu out2=%llu\n",(unsigned long long)dom.returned,(unsigned long long)dom.runtime,(unsigned long long)dom.out[2]);}uint64_t bit=mir_bit(&mimage);checks++;if(dom.out[2]!=bit){failures++;fprintf(stderr,"FAIL domain-bit: versions reads %llu out of the source and machine_ir writes %llu\n",(unsigned long long)dom.out[2],(unsigned long long)bit);}const char*other=HEAD "versions {\nsections 0.1\n}\n";Run alt=run(&image,other,4);cases++;checks++;if(!(alt.returned==349&&alt.runtime==0&&alt.out[2]!=dom.out[2]&&alt.out[2]!=bit)){failures++;fprintf(stderr,"FAIL domain-bit red-source: ret=%llu out2=%llu bit=%llu\n",(unsigned long long)alt.returned,(unsigned long long)alt.out[2],(unsigned long long)bit);}const char*newer=HEAD "versions {\nmachine_ir 0.2\n}\n";Run mv=run(&image,newer,4);cases++;checks++;if(!(mv.returned==348&&mv.runtime==0&&mv.out[3]==2)){failures++;fprintf(stderr,"FAIL domain-bit red-version: ret=%llu minor=%llu\n",(unsigned long long)mv.returned,(unsigned long long)mv.out[3]);}}if(image.memory)nova_host_unmap(&image);if(mimage.memory)nova_host_unmap(&mimage);if(compiled)nt_artifact_free(&a);if(mcompiled)nt_artifact_free(&ma);for(unsigned i=0;i<5;i++)free(sources[i]);for(unsigned i=0;i<MIR_N;i++)free(msources[i]);printf("NTASM_NOVA_VERSIONS checks=%u failures=%u cases=%u\n",checks,failures,cases);return failures?1:0;}
