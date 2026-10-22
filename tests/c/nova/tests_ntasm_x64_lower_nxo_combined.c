#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include "../../../compiler/c/ntasm/formats/object.h"
#include "../../../compiler/c/ntasm/frontend/frontend.h"
#include "../../../compiler/c/ntasm/backend/codegen.h"
#include "../../../compiler/c/ntasm/backend/x64.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* NXO data layout of the combined import + call producer, measured against the
 * real C pipeline.
 *
 * This gate used to compare the producer against nt_object_write fed with a hand
 * built NtObject whose .rdata was the three bytes 34 12 2a with zeta at 0 and
 * alpha at 2. That golden encodes the pre-spec layout: items packed back to back
 * in declaration order. nt_object_write is a pure serialiser, it copies the
 * section bytes the caller hands it, so it could never see a layout divergence
 * and the gate confirmed whatever the producer emitted. The layout oracle is now
 * the C frontend and codegen, nt_frontend_compile_object +
 * nt_codegen_x64_object + nt_object_write, which lays items out by ascending
 * byte-wise unsigned name and aligns each one to min(width,8) exactly as
 * spec/formats/nxo-v0.md requires.
 *
 * nt_object_compile, the canonical builder of the very same C frontend, runs
 * beside the hand assembly as the second reference and must agree with it on
 * every layout field: target, the three section payloads, and each symbol's
 * section, offset, size and role. The two fields the hand assembly cannot share
 * are the module qualified name and the canonical contract text; both are the
 * documented Nova convention, and neither is a layout question.
 *
 * Scope. build_combined_core emits a bare call/ret statement stream against a
 * declared import, and the C frontend refuses that body: a bare ret needs a
 * frame balance proof (503). The layout of a data item is a function of the
 * data declarations alone, so every fixture is measured against a twin source
 * carrying the identical data declarations, the same target and a C expressible
 * body with no import. The C verdict on the real source is reported too, so an
 * ORACLE_FREE is never silent. The .text stream, the import symbol, the entry
 * and the REL32 site are checked separately as the producer's own documented
 * stream; they are not claimed as C parity.
 *
 * One row per fixture, verbatim:
 *   DATA <label> scope=data nova_rdata=<n> nova_data=<n> C_rdata=<n>
 *        C_data=<n> nova_off=<name@off,...> C_off=<name@off,...>
 *        verdict=IDENTICAL|DIVERGES first=<n> <detail>
 */

static unsigned checks, failures, cases;
#define CHECK(c,m) do{checks++;if(!(c)){failures++;fprintf(stderr,"FAIL %s\n",m);}}while(0)
#define CHECKL(c,m,l) do{checks++;if(!(c)){failures++; \
    fprintf(stderr,"FAIL %s [%s]\n",(l),(m));}}while(0)
static char *loadf(const char *p,size_t *n){FILE*f=fopen(p,"rb");if(!f)return NULL;fseek(f,0,SEEK_END);long z=ftell(f);fseek(f,0,SEEK_SET);char*b=z>=0?malloc((size_t)z+1):NULL;if(!b||fread(b,1,(size_t)z,f)!=(size_t)z){free(b);fclose(f);return NULL;}fclose(f);b[z]=0;*n=(size_t)z;return b;}
static uint64_t r64(const uint8_t*b){uint64_t v=0;for(unsigned i=0;i<8;i++)v|=(uint64_t)b[i]<<(i*8);return v;}
static size_t encode_(uint8_t*out,const char*name,NtX64Operand*op,size_t n){
    NtX64Instruction encoded={0};NtX64Context ctx={1,3};
    CHECK(nt_x64_encode(name,op,n,ctx,&encoded)==0,"C x64 oracle");
    memcpy(out,encoded.bytes,encoded.length);return encoded.length;
}
static uint64_t run(const NovaHostImage*i,const char*source,uint8_t*out,size_t capacity){
    NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"context init");
    uint64_t sh=nova_borrow_v2(&c,(void*)source,strlen(source),0),oh=nova_borrow_v2(&c,out,capacity,1);
    uint64_t args[]={sh,strlen(source),oh,capacity};uint64_t code=i->entry(&c,args,4);
    CHECK(c.error==0,"runtime clean");CHECK(nova_context_destroy_v2(&c),"context cleanup");
    cases++;return code;
}
static void rejected(const NovaHostImage*i,const char*source,size_t cap,uint64_t expected,const char*label){
    uint8_t out[2048];memset(out,0xcc,sizeof out);uint64_t code=run(i,source,out,cap);int intact=code==expected;
    for(size_t j=0;j<cap;j++)intact&=out[j]==0xcc;
    CHECK(intact,label);
}

/* ------------------------------------------------------------------ *
 * Contract oracle.
 *
 * Every contract text this gate expects is read out of the C object writer,
 * never copied out of the Nova producer. nt_object_compile is
 * nt_frontend_compile_object + nt_codegen_x64_object + nt_object_write, so
 * the text it hands back is what object_build.c contract_text builds for the
 * declaration in the probe. A probe is a module written here, never a
 * recording of producer output, so a producer that drifted fails the
 * comparison instead of confirming itself. Where the two disagree the case
 * fails and prints both strings.
 * ------------------------------------------------------------------ */

typedef struct { const char *label, *probe, *name; } ContractProbe;

/* Every field contract_text prints is varied below: target, abi, features,
 * section, return type, bound and unbound parameters, the effects triple,
 * the clobbers mask, requires and ensures, and the data form over both data
 * sections and all four widths. stack_aligned is absent on purpose: its
 * literal argument carries no type, so object_build.c cannot print it and
 * nt_object_compile refuses such a module with 800. */
static const ContractProbe contract_probes[] = {
    {"fn_uefi_plain",
     "module d\ntarget x86_64-nexora-uefi\nsection .text {\nexport fn f()->u64\n"
     "effects {}\nclobbers {} {\nreturn 0\n}\n}\n", "f"},
    {"fn_none_plain",
     "module d\ntarget x86_64-nexora-none\nsection .text {\nexport fn f()->u64\n"
     "effects {}\nclobbers {} {\nreturn 0\n}\n}\n", "f"},
    {"fn_abi_efi",
     "module d\ntarget x86_64-nexora-uefi\nsection .text {\nexport fn f()->u64\n"
     "abi efi-x64-v0\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", "f"},
    {"fn_return_u32",
     "module d\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "export fn f(in p:u64 @rdi)->u32\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", "f"},
    {"fn_features_sse2",
     "module d\ntarget x86_64-nexora-uefi\nfeatures {sse2}\nsection .text {\n"
     "export fn f()->u64\neffects {}\nclobbers {}\n"
     "requires {feature(sse2)}\nensures {feature(sse2)} {\nreturn 0\n}\n}\n", "f"},
    {"fn_clobbers_mask",
     "module d\ntarget x86_64-nexora-uefi\nsection .text {\nexport fn f()->u64\n"
     "effects {}\nclobbers {rax,rbx,r12} {\nreturn 0\n}\n}\n", "f"},
    {"fn_effects_flags",
     "module d\ntarget x86_64-nexora-uefi\nsection .text {\nexport fn f()->u64\n"
     "effects {privileged,changes_flags,mmio,io_port,msr,control,interrupt_state,"
     "reads_mem,writes_mem}\nclobbers {} {\nreturn 0\n}\n}\n", "f"},
    {"fn_effects_spaces",
     "module d\ntarget x86_64-nexora-uefi\nsection .text {\nexport fn f()->u64\n"
     "effects {reads_mem(user),reads_mem(mmio),writes_mem(kernel)}\nclobbers {} {\n"
     "return 0\n}\n}\n", "f"},
    {"fn_params_bound",
     "module d\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "export fn f(in a:ptr<user,u64> @rdi,in b:u64 @rsi,out c:u64 @r8)->u64\n"
     "effects {}\nclobbers {} {\nmov r8, 0\nreturn 0\n}\n}\n", "f"},
    {"fn_params_unbound",
     "module d\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "export fn f(in a:u64,in b:u32,in c:ptr<user,u64>)->u64\n"
     "effects {}\nclobbers {} {\nreturn 0\n}\n}\n", "f"},
    {"fn_params_mixed",
     "module d\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "export fn f(in a:ptr<user,u64> @rdi,in b:u64,out c:u64 @r8)->u64\n"
     "effects {writes_mem}\nclobbers {rax} {\nmov r8, 0\nreturn 0\n}\n}\n", "f"},
    {"fn_predicates",
     "module d\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "export fn f(in p:ptr<mmio,u8> @rdi)->u64\neffects {}\nclobbers {}\n"
     "requires {non_null(p)}\nensures {non_null(p)} {\nreturn 0\n}\n}\n", "f"},
    {"fn_predicates_sorted",
     "module d\ntarget x86_64-nexora-uefi\nfeatures {sse2}\nsection .text {\n"
     "export fn f(in p:ptr<user,u64> @rdi,in q:ptr<user,u64> @rsi)->u64\n"
     "effects {}\nclobbers {}\n"
     "requires {non_null(q),non_null(p),feature(sse2)}\n"
     "ensures {non_null(p),non_null(q)} {\nreturn 0\n}\n}\n", "f"},
    {"fn_everything",
     "module d\ntarget x86_64-nexora-uefi\nfeatures {sse2}\nsection .text {\n"
     "export fn f(in p:ptr<user,u64> @rdi,in q:u64,out r:u64 @r8)->u64\n"
     "effects {privileged,changes_flags,reads_mem,writes_mem}\nclobbers {rax,rbx,r12}\n"
     "requires {feature(sse2),non_null(p)}\nensures {non_null(p)} {\nmov r8, 0\nreturn 0\n}\n}\n",
     "f"},
    {"fn_everything_bare",
     "module d\ntarget x86_64-nexora-none\nfeatures {sse2}\nsection .text {\n"
     "export fn f(in p:ptr<user,u64> @rdi,in q:u64,out r:u64 @r8)->u64\n"
     "effects {privileged,changes_flags,reads_mem,writes_mem}\nclobbers {rax,rbx,r12}\n"
     "requires {feature(sse2),non_null(p)}\nensures {non_null(p)} {\nmov r8, 0\nreturn 0\n}\n}\n",
     "f"},
    {"data_rdata_u8",
     "module d\ntarget x86_64-nexora-uefi\nsection .rdata {\nexport data item:u8=1\n}\n"
     "section .text {\nexport fn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", "item"},
    {"data_rdata_u16",
     "module d\ntarget x86_64-nexora-uefi\nsection .rdata {\nexport data item:u16=1\n}\n"
     "section .text {\nexport fn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", "item"},
    {"data_rdata_u32",
     "module d\ntarget x86_64-nexora-uefi\nsection .rdata {\nexport data item:u32=1\n}\n"
     "section .text {\nexport fn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", "item"},
    {"data_rdata_u64",
     "module d\ntarget x86_64-nexora-uefi\nsection .rdata {\nexport data item:u64=1\n}\n"
     "section .text {\nexport fn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", "item"},
    {"data_data_u8",
     "module d\ntarget x86_64-nexora-uefi\nsection .data {\nexport data item:u8=1\n}\n"
     "section .text {\nexport fn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", "item"},
    {"data_data_u16",
     "module d\ntarget x86_64-nexora-uefi\nsection .data {\nexport data item:u16=1\n}\n"
     "section .text {\nexport fn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", "item"},
    {"data_data_u32",
     "module d\ntarget x86_64-nexora-uefi\nsection .data {\nexport data item:u32=1\n}\n"
     "section .text {\nexport fn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", "item"},
    {"data_data_u64",
     "module d\ntarget x86_64-nexora-uefi\nsection .data {\nexport data item:u64=1\n}\n"
     "section .text {\nexport fn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n", "item"},
    {NULL, NULL, NULL}};
#define CONTRACT_PROBE_COUNT ((unsigned)(sizeof contract_probes / sizeof contract_probes[0] - 1))

/* The bare source name inside a module qualified C symbol name. */
static const char *contract_tail(const char *qualified)
{
    const char *dot = strrchr(qualified, '.');
    return dot ? dot + 1 : qualified;
}

static char *contract_dup(const char *s)
{
    size_t n = s ? strlen(s) : 0;
    char *copy = malloc(n + 1);
    if (!copy) { CHECK(0, "contract text copy allocated"); return NULL; }
    if (n) memcpy(copy, s, n);
    copy[n] = 0;
    return copy;
}

/* The contract the C object writer built for the symbol whose qualified name
 * ends in "." + name, searched inside a C built object. */
static const char *c_symbol_contract(const NtObject *o, const char *name)
{
    size_t k, nl = strlen(name);
    for (k = 0; k < o->symbol_count; k++) {
        const char *written = o->symbols[k].name;
        size_t l = written ? strlen(written) : 0;
        if (l > nl && written[l - 1 - nl] == '.' && !memcmp(written + l - nl, name, nl))
            return o->symbols[k].contract;
    }
    return NULL;
}

/* The name the C object writer gave that symbol, in full, inside the object `o`
 * it already built. The writer qualifies every symbol with the module of the
 * source it was given (object_build.c nt_object_compile), so the bare name the
 * frontend image carries is NOT the name the object carries, and the qualified
 * string is also the sort key object.c line 65 checks the table against. The
 * expectations this gate serialises are compared to the producer byte for
 * byte, so they take the name from the writer rather than from a literal. NULL
 * when the C object declares no such symbol. */
static const char *c_symbol_name(const NtObject *o, const char *name)
{
    size_t k, nl = strlen(name);
    for (k = 0; k < o->symbol_count; k++) {
        const char *written = o->symbols[k].name;
        size_t l = written ? strlen(written) : 0;
        if (l > nl && written[l - 1 - nl] == '.' && !memcmp(written + l - nl, name, nl))
            return written;
    }
    return NULL;
}

/* A private copy of that text, for an object the C pipeline already built. */
static char *c_contract_of(const NtObject *o, const char *name)
{
    const char *written = o->symbol_count ? c_symbol_contract(o, name) : NULL;
    if (!written)
        fprintf(stderr, "C_CONTRACT_MISSING name=%s symbols=%zu\n", name, o->symbol_count);
    return written ? contract_dup(written) : NULL;
}

/* The same text from a fresh nt_object_compile of `probe`. */
static char *c_contract(const char *probe, const char *name)
{
    NtFInput input = {"d", probe, strlen(probe)};
    NtObject object;
    NtDiagnostic error;
    char *found = NULL;
    memset(&object, 0, sizeof object);
    memset(&error, 0, sizeof error);
    if (!nt_object_compile(&input, 1, &object, &error)) {
        fprintf(stderr, "C_CONTRACT_REFUSED name=%s code=%u %s\n", name, error.code,
                error.message);
        return NULL;
    }
    found = c_contract_of(&object, name);
    nt_object_free(&object);
    return found;
}

/* The NAME the C object writer gave that symbol, in full, from a fresh
 * nt_object_compile of `probe`, as a string the caller frees. The C writer
 * qualifies every symbol with the module of the source it was given
 * (object_build.c nt_object_compile), so a fixture that wants to name a
 * producer symbol has to ask the writer what that symbol is called rather than
 * spell the answer out: a bare name, a wrong prefix and a missing dot are three
 * different answers and only the writer knows which one the object carries.
 * NULL when the writer refused the probe or declares no such symbol. */
static char *c_name_of(const char *probe, const char *name)
{
    NtFInput input = {"d", probe, probe ? strlen(probe) : 0};
    NtObject object;
    NtDiagnostic error;
    char *found = NULL;
    size_t k, nl;
    if (!name) return NULL;
    nl = strlen(name);
    memset(&object, 0, sizeof object);
    memset(&error, 0, sizeof error);
    if (!nt_object_compile(&input, 1, &object, &error)) {
        fprintf(stderr, "C_NAME_REFUSED name=%s code=%u %s\n", name, error.code,
                error.message);
        return NULL;
    }
    for (k = 0; k < object.symbol_count; k++) {
        const char *written = object.symbols[k].name;
        size_t l = written ? strlen(written) : 0;
        if (l > nl && written[l - 1 - nl] == '.' && !memcmp(written + l - nl, name, nl)) {
            found = (char *)malloc(l + 1);
            if (found) memcpy(found, written, l + 1);
            else fprintf(stderr, "C_NAME_NOMEM name=%s\n", name);
            break;
        }
    }
    if (!found) fprintf(stderr, "C_NAME_ABSENT name=%s symbols=%zu\n", name,
                        object.symbol_count);
    nt_object_free(&object);
    return found;
}

/* A second image holding only the Nova NXO text accessors, so the contract
 * texts the C writer produced can be read back by a Nova producer without
 * disturbing the entry this gate drives. */
static int contract_image(NovaHostImage *image, NtArtifact *artifact)
{
    const char *paths[] = {"tests/nova/tests/nxo-inspect-text-entry.nova",
                           "compiler/nova/inspectors/nxo_inspect.nova",
                           "compiler/nova/formats/nxo/nxo.nova",
                           "compiler/nova/formats/pe/pe.nova"};
    char *sources[4] = {0};
    NtFInput inputs[4];
    unsigned i;
    int all = 1, compiled;
    for (i = 0; i < 4; i++) {
        size_t n = 0;
        sources[i] = loadf(paths[i], &n);
        inputs[i] = (NtFInput){paths[i], sources[i], n};
        if (!sources[i]) all = 0;
    }
    CHECK(all, "contract accessor sources load");
    compiled = all && nova_compile_many_v2(inputs, 4, artifact);
    CHECK(compiled, "contract accessor modules compile");
    if (!compiled) {
        fprintf(stderr, "E%u %zu:%zu %s\n", artifact->error.code, artifact->error.line,
                artifact->error.column, artifact->error.message);
        for (i = 0; i < 4; i++) free(sources[i]);
        return 0;
    }
    if (!nova_host_map(artifact, image)) {
        CHECK(0, "contract accessor image maps");
        for (i = 0; i < 4; i++) free(sources[i]);
        return 0;
    }
    for (i = 0; i < 4; i++) free(sources[i]);
    CHECK(image->memory != NULL, "contract accessor image is mapped");
    return image->memory != NULL;
}

#define CONTRACT_OUT_CAPACITY 2048

/* One probe: the C object writer builds it, nt_object_write serialises it,
 * nt_object_read reads it back, and the Nova text accessor reads the same
 * bytes out of the same file. All of them must return the same string, and
 * that string must be longer than the two byte placeholder the producer used
 * to write, so a regression to the placeholder cannot pass here. */
static void contract_round_trip(const NovaHostImage *ci, const ContractProbe *p)
{
    static uint8_t text[CONTRACT_OUT_CAPACITY];
    uint64_t length[1];
    NtObject canon = {0}, read = {0};
    NtBuffer file = {0};
    NtDiagnostic error = {0};
    NtFInput input = {"d", p->probe, strlen(p->probe)};
    char *expected = NULL;
    size_t want = 0, index = 0, k;
    int found = 0;

    cases++;
    if (!nt_object_compile(&input, 1, &canon, &error)) {
        CHECK(0, "contract probe: the C object writer builds the probe");
        fprintf(stderr, "CONTRACT_ORACLE_REFUSED %s code=%u %s\n", p->label, error.code,
                error.message);
        return;
    }
    CHECK(1, "contract probe: the C object writer builds the probe");
    expected = c_contract_of(&canon, p->name);
    CHECK(expected != NULL, "contract probe: the C object writer wrote the contract");
    if (!expected) { nt_object_free(&canon); return; }
    want = strlen(expected);
    CHECK(want > 2, "contract probe: the C contract is longer than the v0 placeholder");
    CHECK(nt_object_write(&canon, &file, &error), "contract probe: nt_object_write serialises it");
    CHECK(file.bytes && nt_object_read(file.bytes, file.size, &read, &error),
          "contract probe: nt_object_read reads it back");
    for (k = 0; read.symbols && k < read.symbol_count; k++)
        if (!strcmp(contract_tail(read.symbols[k].name), p->name)) { index = k; found = 1; break; }
    CHECK(found, "contract probe: nt_object_read kept the probed symbol");
    if (found)
        CHECK(!strcmp(read.symbols[index].contract, expected),
              "contract probe: nt_object_read recovers the C contract byte for byte");
    if (file.bytes && found) {
        NovaContextV2 c = {0};
        uint64_t args[8], code = UINT64_C(0xffffffffffffffff);
        memset(text, 0xcc, sizeof text);
        length[0] = UINT64_C(0xcccccccccccccccc);
        CHECK(nova_context_init_v2(&c), "contract probe: accessor context init");
        args[0] = nova_borrow_v2(&c, file.bytes, file.size, 0);
        args[1] = file.size;
        args[2] = (uint64_t)index;
        args[3] = nova_borrow_v2(&c, text, sizeof text, 1);
        args[4] = (uint64_t)sizeof text;
        args[5] = nova_borrow_v2(&c, length, sizeof length, 1);
        args[6] = 1; /* the flat slot carries the element count of a buf<u64> */
        args[7] = 1; /* mode 1 copies the contract, mode 0 the name */
        code = ci->entry(&c, args, 8);
        CHECK(c.error == 0, "contract probe: accessor runtime clean");
        CHECK(nova_context_destroy_v2(&c), "contract probe: accessor context cleanup");
        CHECK(code == 0, "contract probe: the Nova accessor returns the contract");
        if (code == 0) {
            CHECK(length[0] == want, "contract probe: the accessor reports the C length");
            CHECK(length[0] == want && !memcmp(text, expected, want),
                  "contract probe: the Nova accessor returns the C contract byte for byte");
        }
    }
    if (read.symbols) nt_object_free(&read);
    free(file.bytes);
    nt_object_free(&canon);
    free(expected);
}

/* Two probes whose declarations differ must not collapse onto one contract
 * string, so the table is variation and not decoration. */
static void contract_distinct(void)
{
    char *texts[64];
    unsigned k, j;
    unsigned collisions = 0, refusals = 0;
    for (k = 0; k < CONTRACT_PROBE_COUNT; k++) texts[k] = NULL;
    for (k = 0; k < CONTRACT_PROBE_COUNT; k++) {
        NtFInput input = {"d", (char *)contract_probes[k].probe,
                          strlen(contract_probes[k].probe)};
        NtObject canon = {0};
        NtDiagnostic error = {0};
        if (!nt_object_compile(&input, 1, &canon, &error)) { refusals++; continue; }
        texts[k] = c_contract_of(&canon, contract_probes[k].name);
        nt_object_free(&canon);
    }
    for (k = 0; k < CONTRACT_PROBE_COUNT; k++)
        for (j = k + 1; j < CONTRACT_PROBE_COUNT; j++)
            if (texts[k] && texts[j] && !strcmp(texts[k], texts[j])) {
                collisions++;
                fprintf(stderr, "CONTRACT_COLLISION %s == %s [%s]\n",
                        contract_probes[k].label, contract_probes[j].label, texts[k]);
            }
    CHECK(refusals == 0, "contract probes: the C object writer builds every probe");
    CHECK(collisions == 0, "contract probes: distinct declarations give distinct texts");
    for (k = 0; k < CONTRACT_PROBE_COUNT; k++) free(texts[k]);
}

/* The whole table, then the distinctness sweep.
 *
 * The suite counts as a case of its own, and that line was lost: the count went
 * 130 -> 129 while every label reaching the DATA row stayed byte-identical at
 * 102, which is why it read as a dropped fixture when nothing had been
 * dropped. Traced rather than guessed -- every case this gate runs was
 * enumerated at run time (106 producer runs + 23 probes + this one) and the
 * missing 1 was exactly this aggregate. The distinctness sweep is a case in
 * its own right: it asks the reference to build all 23 probes and compares
 * their contract texts pairwise, and it is the only place a collision between
 * two different declarations can be seen. Without the counter the suite still
 * ran and still asserted, so nothing was silently unexercised -- but a case
 * count that falls by one for a reason nobody wrote down is a number this
 * project has no way to trust, which is the defect, not the missing digit. */
static void contract_suite(const NovaHostImage *ci)
{
    unsigned k;
    for (k = 0; k < CONTRACT_PROBE_COUNT; k++) contract_round_trip(ci, contract_probes + k);
    contract_distinct();
    cases++;
}

/* Compares a produced object's contract text against the C object writer's,
 * never against a literal. */
static int contract_verdict_with(const char *label, const NtObject *o, const NtObject *canon,
                                 const char *extra_name, const char *extra_contract)
{
    size_t j;
    int same = 1;
    for (j = 0; o->symbols && j < o->symbol_count; j++) {
        const char *want = NULL;
        /* `extra_name` is the WHOLE name the C reference gives the symbol, and
         * the match is a whole string comparison. It used to be a bare fixture
         * name compared against contract_tail, which is a suffix match: under
         * it a symbol qualified with the WRONG module still matched, and so
         * did the import before this lot, because the alias was the tail of
         * neither the reference's name nor the producer's. Name against name
         * is the only comparison that tells those apart. */
        if (extra_name && !strcmp(o->symbols[j].name, extra_name))
            want = extra_contract;
        if (!want) want = c_symbol_contract(canon, contract_tail(o->symbols[j].name));
        if (!want) {
            same = 0;
            fprintf(stderr, "CONTRACT %s absent from the C table name=%s\n", label,
                    o->symbols[j].name);
            continue;
        }
        if (strcmp(o->symbols[j].contract, want)) {
            same = 0;
            fprintf(stderr, "CONTRACT %s name=%s nova=[%s] C=[%s]\n", label,
                    o->symbols[j].name, o->symbols[j].contract, want);
        }
    }
    fprintf(stderr, "CONTRACT %s symbols=%zu verdict=%s\n", label,
            o->symbol_count ? o->symbol_count : (size_t)0,
            same ? "CANONICAL" : "DIVERGES");
    return same;
}

/* ------------------------------------------------------------------ *
 * C frontend oracle
 * ------------------------------------------------------------------ */

typedef struct {
    NtObject object;
    void *symbols,*sorted,*order,*relocations,*names;
} Assembly;
static void assembly_free(Assembly *a){free(a->sorted);free(a->symbols);free(a->order);
    free(a->relocations);free(a->names);memset(a,0,sizeof *a);}

/* object.c rejects a symbol table that is not strictly ascending by strcmp, so
 * the table is sorted here by name with the declaration index as the final
 * tiebreak, exactly as spec/formats/nxo-v0.md orders the names. */
typedef struct { const char *name; size_t index; } NameOrder;
static int name_compare(const void*x,const void*y){
    int order=strcmp(((const NameOrder *)x)->name,((const NameOrder *)y)->name);
    if(order)return order;
    return ((const NameOrder *)x)->index<((const NameOrder *)y)->index?-1:1;
}

static int assemble(const NtCodeImage *image,const NtObject *canon,Assembly *a,char *why,size_t cap){
    size_t j,exported=0,total=image->symbol_count?image->symbol_count:1;
    NtObjectSymbol *symbols=calloc(total,sizeof *symbols);
    NtObjectReloc *relocs=calloc(image->relocation_count?image->relocation_count:1,sizeof *relocs);
    char (*names)[512]=calloc(total,sizeof *names);
    NameOrder *order=calloc(total,sizeof *order);
    memset(a,0,sizeof *a);
    if(!symbols||!relocs||!names||!order){
        free(symbols);free(relocs);free(names);free(order);
        snprintf(why,cap,"assembly allocation failed");return 0;
    }
    for(j=0;j<image->symbol_count;j++){
        const NtCodeSymbol *s=image->symbols+j;
        const char *qualified=c_symbol_name(canon,s->name);
        int n;
        if(!qualified){
            free(symbols);free(relocs);free(names);free(order);
            snprintf(why,cap,"assembly: the C object writer names no symbol %s",s->name);
            return 0;
        }
        n=snprintf(names[j],sizeof names[j],"%s",qualified);
        if(n<=0||(size_t)n>=sizeof names[j]){
            free(symbols);free(relocs);free(names);free(order);
            snprintf(why,cap,"assembly name overflow");return 0;
        }
        symbols[j].name=names[j];
        symbols[j].contract=(char*)c_symbol_contract(canon,contract_tail(s->name));
        if(!symbols[j].contract){
            free(symbols);free(relocs);free(names);free(order);
            snprintf(why,cap,"assembly: the C object writer has no contract for %s",
                     s->name);return 0;}
        symbols[j].section=s->section;symbols[j].offset=s->offset;symbols[j].size=s->size;
        /* codegen gives an unresolved import section0/size0/flags8 with a
         * function id, and a data item flags0 or flags1 with a variable id */
        if(s->function_id&&!(s->flags&1u)&&s->section==0)
            symbols[j].flags=NT_OBJECT_FUNCTION|NT_OBJECT_IMPORT;
        else
            symbols[j].flags=(s->function_id?NT_OBJECT_FUNCTION:NT_OBJECT_VARIABLE)|
                             ((s->flags&1u)?NT_OBJECT_EXPORT:0u);
        order[j].name=names[j];order[j].index=j;
        if(s->function_id&&(s->flags&1u)&&s->section==NT_CODE_SECTION_TEXT)exported++;
    }
    if(exported!=1){
        free(symbols);free(relocs);free(names);free(order);
        snprintf(why,cap,"assembly: %zu exported .text functions",exported);return 0;
    }
    qsort(order,image->symbol_count,sizeof *order,name_compare);
    a->symbols=symbols;a->order=order;a->relocations=relocs;a->names=names;
    a->object.target=1;
    a->sorted=calloc(total,sizeof *symbols);
    if(!a->sorted){assembly_free(a);snprintf(why,cap,"assembly table allocation failed");return 0;}
    a->object.symbols=a->sorted;
    for(j=0;j<image->symbol_count;j++){
        /* image->symbols is walked in the same order as `symbols` by the loop
         * above -- symbols[j] is filled from image->symbols[j] -- and only the
         * SORT is applied afterwards, through order[]. */
        const NtCodeSymbol *s=image->symbols+order[j].index;
        a->object.symbols[j]=symbols[order[j].index];
        /* The entry is the exported .text function NAMED main, found again in
         * the sorted table because object.c indexes it there. The name test is
         * not decoration: object_build.c:343-347 sets entry_symbol only for the
         * symbol at image.entry whose function is exported AND whose name is
         * "main", and codegen.c:1557-1562 only ever sets image.entry for such a
         * function. Deriving it from the export bit alone named an entry for
         * an exported helper, which the reference writes as 0. */
        if(symbols[order[j].index].section==NT_OBJECT_TEXT&&
           (symbols[order[j].index].flags&NT_OBJECT_EXPORT)&&
           (symbols[order[j].index].flags&NT_OBJECT_FUNCTION)&&
           !strcmp(s->name,"main"))
            a->object.entry_symbol=(uint32_t)j+1;
    }
    a->object.symbol_count=image->symbol_count;
    a->object.relocation_count=image->relocation_count;
    a->object.relocations=relocs;
    for(j=0;j<image->relocation_count;j++){
        const NtCodeReloc *r=image->relocations+j;
        size_t k;uint32_t target=0;
        for(k=0;k<image->symbol_count;k++)
            if(r->target_function&&image->symbols[k].function_id==r->target_function){
                target=(uint32_t)k+1;break;
            }
        if(!target){assembly_free(a);snprintf(why,cap,"assembly: relocation has no target");return 0;}
        relocs[j]=(NtObjectReloc){r->source_section,r->kind,r->offset,target,r->addend};
    }
    a->object.sections[0]=(NtBuffer){image->bytes,image->size,image->capacity};
    a->object.sections[1]=(NtBuffer){image->rdata.bytes,image->rdata.size,image->rdata.capacity};
    a->object.sections[2]=(NtBuffer){image->data.bytes,image->data.size,image->data.capacity};
    return 1;
}

typedef struct { int ok; NtBuffer file; NtObject canonical; char why[256]; } Reference;
static void reference_free(Reference *r){free(r->file.bytes);r->file.bytes=NULL;
    if(r->canonical.symbols)nt_object_free(&r->canonical);
    r->ok=0;}

/* Names are matched on their unqualified tail so the module qualified
 * canonical table and the bare name hand assembly can be walked independently. */
static const char *tail_of(const char *name){const char *dot=strrchr(name,'.');return dot?dot+1:name;}

static int same_layout(const NtObject *a,const NtObject *b){
    size_t j,k;
    if(a->target!=b->target||a->symbol_count!=b->symbol_count||
       a->relocation_count!=b->relocation_count)return 0;
    for(j=0;j<3;j++)
        if(a->sections[j].size!=b->sections[j].size||
           (a->sections[j].size&&memcmp(a->sections[j].bytes,b->sections[j].bytes,
                                        a->sections[j].size)))return 0;
    for(j=0;j<a->symbol_count;j++){
        for(k=0;k<b->symbol_count;k++){
            if(strcmp(tail_of(a->symbols[j].name),tail_of(b->symbols[k].name)))continue;
            if(a->symbols[j].section!=b->symbols[k].section||
               a->symbols[j].offset!=b->symbols[k].offset||
               a->symbols[j].size!=b->symbols[k].size||
               a->symbols[j].flags!=b->symbols[k].flags)return 0;
            break;
        }
        if(k==b->symbol_count)return 0;
    }
    for(j=0;j<a->relocation_count;j++){
        for(k=0;k<b->relocation_count;k++)
            if(a->relocations[j].section==b->relocations[k].section&&
               a->relocations[j].kind==b->relocations[k].kind&&
               a->relocations[j].offset==b->relocations[k].offset&&
               a->relocations[j].addend==b->relocations[k].addend)break;
        if(k==b->relocation_count)return 0;
    }
    return 1;
}

static int reference_for(const char *source,Reference *ref){
    NtFInput input={"m",source,strlen(source)};
    NtFProgram program;NtCodeImage image;NtCodeDiagnostic cd;NtDiagnostic error;
    Assembly assembly;uint32_t canonical_entry=0;size_t k;
    memset(ref,0,sizeof *ref);
    memset(&program,0,sizeof program);memset(&image,0,sizeof image);
    memset(&cd,0,sizeof cd);memset(&error,0,sizeof error);memset(&assembly,0,sizeof assembly);
    { NtFInput again={"m",source,strlen(source)};
      if(!nt_object_compile(&again,1,&ref->canonical,&error)){
        snprintf(ref->why,sizeof ref->why,"nt_object_compile %u %s",error.code,error.message);
        return 0;
      } }
    { char *probe=c_contract(source,"main");
      const char *held=ref->canonical.symbol_count?c_symbol_contract(&ref->canonical,"main"):NULL;
      if(!probe||!held||strcmp(probe,held)){
          snprintf(ref->why,sizeof ref->why,"nt_object_compile: the main contract is not stable");
          free(probe);return 0;
      }
      free(probe); }
    if(!nt_frontend_compile_object(&input,1,&program)){
        snprintf(ref->why,sizeof ref->why,"frontend %u %s",
                 program.diagnostic_count?program.diagnostics[0].code:0u,
                 program.diagnostic_count?program.diagnostics[0].message:"no diagnostic");
        nt_frontend_free(&program);return 0;
    }
    if(!nt_codegen_x64_object(&program,&image,&cd)){
        snprintf(ref->why,sizeof ref->why,"codegen %u %s",cd.code,cd.message);
        nt_code_image_free(&image);nt_frontend_free(&program);return 0;
    }
    if(!assemble(&image,&ref->canonical,&assembly,ref->why,sizeof ref->why)){
        nt_code_image_free(&image);nt_frontend_free(&program);return 0;
    }
    if(!nt_object_write(&assembly.object,&ref->file,&error)){
        snprintf(ref->why,sizeof ref->why,"nt_object_write %u %s",error.code,error.message);
        assembly_free(&assembly);nt_code_image_free(&image);nt_frontend_free(&program);return 0;
    }
    assembly_free(&assembly);nt_code_image_free(&image);nt_frontend_free(&program);
    /* The canonical entry is READ, not demanded. This used to scan for any
     * exported .text function and REFUSE the source when it found none, which
     * is the same rubber stamp in a second place: entry_symbol = 0 is a legal
     * object (object.c:79 validates the entry only when it is non-zero), so a
     * source whose main is not exported -- or whose only export is not named
     * main -- produces a perfectly good reference object, and refusing it here
     * meant this oracle could never be shown such a source at all.
     *
     * The scan is kept as a cross-check rather than as the source of the
     * answer: the reference's own entry_symbol is the authority, and a
     * disagreement between the two would mean the C pipeline is not
     * self-consistent, which is worth a red. */
    canonical_entry=ref->canonical.entry_symbol;
    for(k=0;k<ref->canonical.symbol_count;k++)
        if((ref->canonical.symbols[k].flags&(NT_OBJECT_EXPORT|NT_OBJECT_FUNCTION))==
           (NT_OBJECT_EXPORT|NT_OBJECT_FUNCTION)&&ref->canonical.symbols[k].section==NT_OBJECT_TEXT&&
           !strcmp(contract_tail(ref->canonical.symbols[k].name),"main"))
            canonical_entry=(uint32_t)k+1;
    if(canonical_entry&&(canonical_entry>ref->canonical.symbol_count)){
        snprintf(ref->why,sizeof ref->why,"reference entry is out of range");
        free(ref->file.bytes);ref->file.bytes=NULL;nt_object_free(&ref->canonical);return 0;
    }
    ref->ok=1;
    return 1;
}

/* A data item is a symbol in .rdata or .data. An import has section 0 and is
 * not data, and the twins carry no import at all. */
static int is_data(const NtObjectSymbol *s){return s->section==NT_OBJECT_RDATA||s->section==NT_OBJECT_DATA;}

/* The data columns of one divergence row: every data symbol, in table order, as
 * name@offset. */
static void offsets_of(const NtObject *o,char *dst,size_t room){
    size_t used=0,j;dst[0]=0;
    for(j=0;j<o->symbol_count;j++){
        int n;
        if(!is_data(o->symbols+j))continue;
        n=snprintf(dst+used,room-used,"%s%s@%llu",used?",":"",o->symbols[j].name,
                   (unsigned long long)o->symbols[j].offset);
        if(n<0||(size_t)n>=room-used)break;
        used+=(size_t)n;
    }
}
static int data_symbols_match(const NtObject *a,const NtObject *b,char *detail,size_t room){
    size_t j,k,da=0,db=0;
    detail[0]=0;
    for(j=0;j<a->symbol_count;j++)if(is_data(a->symbols+j))da++;
    for(j=0;j<b->symbol_count;j++)if(is_data(b->symbols+j))db++;
    if(da!=db){snprintf(detail,room,"data symbol count %zu vs %zu",da,db);return 0;}
    for(j=0;j<a->symbol_count;j++){
        if(!is_data(a->symbols+j))continue;
        for(k=0;k<b->symbol_count;k++){
            if(!is_data(b->symbols+k))continue;
            if(strcmp(a->symbols[j].name,b->symbols[k].name))continue;
            if(a->symbols[j].section!=b->symbols[k].section||
               a->symbols[j].offset!=b->symbols[k].offset||
               a->symbols[j].size!=b->symbols[k].size||
               a->symbols[j].flags!=b->symbols[k].flags){
                snprintf(detail,room,"%s sec=%u/%u off=%llu/%llu size=%llu/%llu flags=%u/%u",
                         a->symbols[j].name,a->symbols[j].section,b->symbols[k].section,
                         (unsigned long long)a->symbols[j].offset,
                         (unsigned long long)b->symbols[k].offset,
                         (unsigned long long)a->symbols[j].size,
                         (unsigned long long)b->symbols[k].size,
                         a->symbols[j].flags,b->symbols[k].flags);
                return 0;
            }
            break;
        }
        if(k==b->symbol_count){snprintf(detail,room,"%s absent from the C table",a->symbols[j].name);return 0;}
    }
    return 1;
}
/* First differing byte across the two data payloads, -1 when they agree. */
static long first_data_byte(const NtObject *a,const NtObject *b){
    size_t i;
    for(i=0;i<a->sections[1].size||i<b->sections[1].size;i++){
        uint8_t x=i<a->sections[1].size?a->sections[1].bytes[i]:0xcc;
        uint8_t y=i<b->sections[1].size?b->sections[1].bytes[i]:0xcc;
        if(x!=y)return (long)i;
    }
    for(i=0;i<a->sections[2].size||i<b->sections[2].size;i++){
        uint8_t x=i<a->sections[2].size?a->sections[2].bytes[i]:0xcc;
        uint8_t y=i<b->sections[2].size?b->sections[2].bytes[i]:0xcc;
        if(x!=y)return (long)(a->sections[1].size+i);
    }
    return -1;
}
/* Measures the data layout of one produced object against the C pipeline and
 * prints the divergence row. Returns 1 when the layouts agree. */
static int layout_verdict(const char *label,const NtObject *nova,const char *twin,
                          char *detail,size_t room){
    NtObject cref={0};Reference ref;NtDiagnostic error={0};
    char nova_offsets[2048],c_offsets[2048];
    long first;int same;
    detail[0]=0;
    if(!reference_for(twin,&ref)){
        snprintf(detail,room,"ORACLE_FREE twin: %s",ref.why);
        reference_free(&ref);return 0;
    }
    if(!nt_object_read(ref.file.bytes,ref.file.size,&cref,&error)){
        snprintf(detail,room,"C reference read failed");
        reference_free(&ref);return 0;
    }
    if(!same_layout(&ref.canonical,&cref))
        snprintf(detail,room,"hand assembly differs from the canonical C builder");
    same=nova->sections[1].size==cref.sections[1].size&&
         nova->sections[2].size==cref.sections[2].size&&
         first_data_byte(nova,&cref)<0&&
         data_symbols_match(nova,&cref,detail,room)&&detail[0]==0;
    {   char row[128];
        snprintf(row,sizeof row,"c_reference_%s",label);
        if(!contract_verdict_with(row,&cref,&ref.canonical,NULL,NULL)){
            if(same)snprintf(detail,room,
                             "the C written reference does not carry the canonical contract text");
            same=0;
        }
    }
    first=first_data_byte(nova,&cref);
    offsets_of(nova,nova_offsets,sizeof nova_offsets);
    offsets_of(&ref.canonical,c_offsets,sizeof c_offsets);
    fprintf(stderr,"DATA %s scope=data nova_rdata=%zu nova_data=%zu C_rdata=%zu C_data=%zu "
                    "nova_off=%s C_off=%s verdict=%s first=%ld %s\n",
            label,nova->sections[1].size,nova->sections[2].size,
            cref.sections[1].size,cref.sections[2].size,nova_offsets,c_offsets,
            same?"IDENTICAL":"DIVERGES",first,same?"":detail);
    nt_object_free(&cref);
    reference_free(&ref);
    return same;
}

/* ------------------------------------------------------------------ *
 * Fixtures
 * ------------------------------------------------------------------ */

/* section 2 is .rdata, section 3 is .data, width is in bytes. */
typedef struct { const char *name; unsigned width; uint64_t value; unsigned section; } Item;

#define MAX_ITEMS 64
#define SRCROOM 32768
/* The declared import the producer calls, and the bare call/ret body it emits.
 *
 * BODY_N and BODY_C are the producer's source and the reference's twin, and
 * they must declare the SAME program. They used not to: BODY_N said `fn main`
 * and BODY_C said `export fn main`, and the producer -- which hardcoded
 * NT_OBJECT_EXPORT on main rather than reading the declaration -- emitted the
 * same object for both, so the pair agreed in the output while disagreeing in
 * the source. That is what let a producer marking a non-exported main as
 * exported go unseen here.
 *
 * The export bit matters because the reference sets it from `f->exported`
 * (object_build.c:317) and names the entry only for an exported main
 * (object_build.c:343-347, codegen.c:1557-1562). The two bodies still differ,
 * and must: the reference REFUSES a bare `ret` with 503 "ret requires
 * unavailable stack/frame balance proof", so the twin is the only half the
 * reference can be asked about, and the export bit is a declaration byte that
 * survives naming_source's body substitution untouched. */
#define BODY_N "export fn main()->u64\neffects {}\nclobbers {} {\ncall %s()\nret\n}\n"
#define BODY_C "export fn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n"

/* Emits the items in declaration order, which is the order the producer walks
 * them in and, for the C reference, not the order it lays them out in. This
 * producer accepts only exported data declarations inside a data section, so
 * every item carries the export flag. */
static size_t emit_items(char *dst,size_t room,const Item *items,size_t count){
    size_t used=0,i;
    for(i=0;i<count;i++){
        int n=snprintf(dst+used,room-used,"export data %s:u%u=%llu\n",
                       items[i].name,items[i].width*8,(unsigned long long)items[i].value);
        if(n<0||(size_t)n>=room-used)return room+1;
        used+=(size_t)n;
    }
    return used;
}

/* The producer source: the target, a declared import of the named alias, then
 * the data sections and the body that calls it. */
static size_t build_source(char *dst,size_t room,const Item *items,size_t count,
                           const char *target,const char *alias){
    size_t used=(size_t)snprintf(dst,room,"module m\ntarget x86_64-nexora-%s\n"
                                "import api.echo as %s: fn()->u64\neffects {}\nclobbers {}\n",
                                target,alias);
    unsigned sec;
    size_t i,k;
    int n;
    if(used>=room)return room+1;
    for(sec=0;sec<3;sec++){
        n=snprintf(dst+used,room-used,"section %s {\n",sec==0?".rdata":sec==1?".data":".text");
        if(n<0||(size_t)n>=room-used)return room+1;
        used+=(size_t)n;
        if(sec==2){
            n=snprintf(dst+used,room-used,BODY_N,alias);
            if(n<0||(size_t)n>=room-used)return room+1;
            used+=(size_t)n;
        }else{
            for(i=0;i<count;i++)if(items[i].section==(sec==0?2u:3u)){
                k=emit_items(dst+used,room-used,&items[i],1);
                if(k>=room-used)return room+1;
                used+=k;
            }
        }
        n=snprintf(dst+used,room-used,"}\n");
        if(n<0||(size_t)n>=room-used)return room+1;
        used+=(size_t)n;
    }
    if(used>=room)return room+1;
    dst[used]=0;
    return used;
}

/* The twin: the identical data declarations and the identical target, with a C
 * expressible body and no import, so the layout input is the same. */
static size_t build_twin(char *dst,size_t room,const Item *items,size_t count,
                         const char *target){
    size_t used=(size_t)snprintf(dst,room,"module m\ntarget x86_64-nexora-%s\n",target);
    unsigned sec;
    size_t i,k;
    int n;
    if(used>=room)return room+1;
    for(sec=0;sec<3;sec++){
        n=snprintf(dst+used,room-used,"section %s {\n",sec==0?".rdata":sec==1?".data":".text");
        if(n<0||(size_t)n>=room-used)return room+1;
        used+=(size_t)n;
        if(sec==2){
            n=snprintf(dst+used,room-used,"%s",BODY_C);
            if(n<0||(size_t)n>=room-used)return room+1;
            used+=(size_t)n;
        }else{
            for(i=0;i<count;i++)if(items[i].section==(sec==0?2u:3u)){
                k=emit_items(dst+used,room-used,&items[i],1);
                if(k>=room-used)return room+1;
                used+=k;
            }
        }
        n=snprintf(dst+used,room-used,"}\n");
        if(n<0||(size_t)n>=room-used)return room+1;
        used+=(size_t)n;
    }
    if(used>=room)return room+1;
    dst[used]=0;
    return used;
}


/* The last occurrence of `marker` in `text`, or NULL. strrstr is a GNU
 * extension and this harness is compiled -std=c11 -Werror, so the search is
 * written out rather than reached for. */
static const char *last_occurrence(const char *text,const char *marker){
    size_t m=strlen(marker),n=strlen(text),i,at=0;int found=0;
    for(i=0;i+m<=n;i++)if(!memcmp(text+i,marker,m)){at=i;found=1;}
    return found?text+at:NULL;
}

/* The source the naming oracle is asked about: the producer source's own bytes
 * up to and including the brace that opens the main body, then a body the
 * reference accepts. The substitution is forced by a measurement, not chosen:
 * the reference REFUSES the bare `call` / `ret` body with 503 "ret requires
 * unavailable stack/frame balance proof", so it cannot be asked to name the
 * symbols of that exact text. A body contributes no name, so every declaration
 * byte here is the fixture's own, and what the substitution drops is the call
 * site -- which is the alias, and the reference discards the alias. */
static char *naming_source(const char *fixture,const char *call){
    const char *at=last_occurrence(fixture,"clobbers {} {\n");
    size_t keep,room;char *out;int n;
    if(!at)return NULL;
    keep=(size_t)(at-fixture)+strlen("clobbers {} {\n");
    room=keep+strlen(call)+32;out=(char*)malloc(room);if(!out)return NULL;
    n=snprintf(out,room,"%.*sreturn %s()\n}\n}\n",(int)keep,fixture,call);
    if(n<0||(size_t)n>=room){free(out);return NULL;}
    return out;
}

/* That the substitution above is not quietly a different program: the naming
 * source and the fixture must agree on every byte up to the body's opening
 * brace, and the keep count is recomputed here from the fixture rather than
 * carried over, so a change to either half that breaks the agreement fails
 * here instead of silently swapping the program the oracle is asked about. The
 * export bit is a DECLARATION byte, so it is inside the kept prefix -- which is
 * what makes the entry this gate compares against the fixture's own. */
static void naming_source_is_the_fixture(const char *fixture,const char *derived,
                                         const char *label){
    const char *at=last_occurrence(fixture,"clobbers {} {\n");
    size_t keep;
    CHECKL(at!=NULL,"the fixture's main body opens where the naming source assumes",label);
    if(!at)return;
    keep=(size_t)(at-fixture)+strlen("clobbers {} {\n");
    CHECKL(derived&&strlen(derived)>=keep&&!memcmp(derived,fixture,keep),
           "the naming source is the fixture's own declarations, byte for byte",label);
}

/* THE ENTRY ORACLE: asked, never stated.
 *
 * The entry_symbol the C reference wrote for `source`, or UINT32_MAX when the
 * reference refused the source. It is read out of the object the reference
 * itself built; nothing here reconstructs it.
 *
 * WHY IT IS NOT A LITERAL. This harness used to locate the twin's main BY NAME
 * in the produced table and require entry_symbol to equal that index, and a
 * sibling harness wrote `oracle.entry_symbol = 2` outright. Both stated an
 * answer instead of asking one, and both were blind in the same direction: a
 * producer that named an entry for a program the reference gives no entry to
 * agreed with its own oracle, so the two could not be told apart.
 *
 * WHY THE REFERENCE'S ANSWER IS NOT ALWAYS NON-ZERO. object_build.c:337-351
 * sets entry_symbol only for the symbol at image.entry whose function is
 * exported AND whose name is "main", and codegen.c:1557-1562 sets image.entry
 * only for a function that is exported and named main. So a non-exported main,
 * a module with no main, and an exported function under any other name all
 * yield 0 -- and 0 is a legal object, since object.c:79 validates the entry
 * only when it is non-zero. An oracle that demanded a non-zero entry could not
 * be shown any of those three shapes. */
static uint32_t c_reference_entry(const char *source){
    NtObject o;NtDiagnostic e;uint32_t entry;
    memset(&o,0,sizeof o);memset(&e,0,sizeof e);
    if(!nt_object_compile(&(NtFInput){"entry",(char*)source,strlen(source)},1,&o,&e)){
        fprintf(stderr,"ENTRY_ORACLE_REFUSED code=%u %s\n",e.code,e.message);
        nt_object_free(&o);return UINT32_MAX;
    }
    entry=o.entry_symbol;
    nt_object_free(&o);
    return entry;
}

/* The name the C reference writes for the one symbol carrying `flags` in
 * `section` of the object it builds for `source`. Selection is by the
 * reference's own metadata and never by recognising a name. */
static char *c_reference_name(const char *source,uint32_t section,uint32_t flags){
    NtObject o;NtDiagnostic e;char *found=NULL;size_t k,hits=0,at=0;
    memset(&o,0,sizeof o);memset(&e,0,sizeof e);
    if(!nt_object_compile(&(NtFInput){"naming",(char*)source,strlen(source)},1,&o,&e)){
        fprintf(stderr,"REFERENCE_REFUSED %u %s\n",e.code,e.message);
        nt_object_free(&o);return NULL;}
    for(k=0;k<o.symbol_count;k++)
        if(o.symbols[k].section==section&&o.symbols[k].flags==flags){hits++;at=k;}
    if(hits==1){const char *nm=o.symbols[at].name;size_t l=nm?strlen(nm):0;
        found=(char*)malloc(l+1);if(found){if(l)memcpy(found,nm,l);found[l]=0;}}
    else fprintf(stderr,"REFERENCE_NAME_AMBIGUOUS section=%u flags=%u hits=%zu\n",
                 section,flags,hits);
    nt_object_free(&o);return found;
}

/* The contract text the C reference wrote for the one symbol carrying `flags`
 * in `section`. Same selection rule as c_reference_name and for the same
 * reason. */
static char *c_reference_contract(const char *source,uint32_t section,uint32_t flags){
    NtObject o;NtDiagnostic e;char *found=NULL;size_t k,hits=0,at=0;
    memset(&o,0,sizeof o);memset(&e,0,sizeof e);
    if(!nt_object_compile(&(NtFInput){"contract",(char*)source,strlen(source)},1,&o,&e)){
        fprintf(stderr,"CONTRACT_ORACLE_REFUSED %u %s\n",e.code,e.message);
        nt_object_free(&o);return NULL;}
    for(k=0;k<o.symbol_count;k++)
        if(o.symbols[k].section==section&&o.symbols[k].flags==flags){hits++;at=k;}
    if(hits==1){const char *t=o.symbols[at].contract;size_t l=t?strlen(t):0;
        found=(char*)malloc(l+1);if(found){if(l)memcpy(found,t,l);found[l]=0;}}
    else fprintf(stderr,"CONTRACT_ORACLE_AMBIGUOUS section=%u flags=%u hits=%zu\n",
                 section,flags,hits);
    nt_object_free(&o);return found;
}
static uint32_t index_of(const NtObject *o,const char *name){
    for(size_t j=0;j<o->symbol_count;j++)if(!strcmp(o->symbols[j].name,name))return (uint32_t)j+1;
    return 0;
}

/* Runs one fixture through the producer and its twin through the C pipeline,
 * then prints the divergence row. The verdict is a measurement. */

/* The import the producer names is declared by the source and not by the twin,
 * so its contract is read from a module carrying that same import declaration
 * in the same target. The symbol is found by the reference's own section and
 * flag word, not by a spelling: the comment that used to stand here said the
 * C builder "names an unresolved import by the module it imports from,
 * api.echo, and not by the local alias, so the trailing component of that name
 * is the lookup key", and looked the contract up by the suffix "echo". That is
 * the same suffix match the naming rule cannot survive, and it was the reason
 * a wrong name went unnoticed here. The contract text mentions neither the
 * module nor the alias, so the reference's flag word is the whole identity. */
static char *import_probe(const char *target, const char *alias)
{
    static char storage[512];
    int n = snprintf(storage, sizeof storage,
                     "module d\ntarget x86_64-nexora-%s\n"
                     "import api.echo as %s: fn()->u64\neffects {}\nclobbers {}\n",
                     target, alias);
    if (n <= 0 || (size_t)n >= sizeof storage) return NULL;
    return c_reference_contract(storage, 0, NT_OBJECT_IMPORT | NT_OBJECT_FUNCTION);
}
static void data_case(const NovaHostImage *image,const char *label,const char *source,
                      const char *twin,const char *target,const char *alias,size_t items){
    uint8_t out[65536];
    uint64_t code,size;
    NtObject nova={0};
    NtDiagnostic error={0};
    char *ref_import=NULL;
    char detail[512];
    memset(out,0xcc,sizeof out);
    code=run(image,source,out,sizeof out);
    size=r64(out);
    CHECKL(code==0,"producer accepts the fixture",label);
    if(code!=0){fprintf(stderr,"DATA %s producer code=%llu\n",label,(unsigned long long)code);return;}
    CHECKL(size<=sizeof out-8,"producer output fits",label);
    if(size>sizeof out-8)return;
    CHECKL(nt_object_read(out+8,(size_t)size,&nova,&error),"C NXO read",label);
    CHECKL(nt_object_validate(&nova,&error),"C NXO validate",label);
    /* The name the C reference gives THIS source's unresolved import, asked
     * once and kept for both the structural check below and the contract check
     * after it: the two must agree about which symbol is the import, and asking
     * once is what makes that a fact about the fixture rather than two
     * derivations free to drift apart. */
    {
        char *naming=naming_source(source,alias);
        ref_import=naming?c_reference_name(naming,0,NT_OBJECT_IMPORT|NT_OBJECT_FUNCTION):NULL;
        free(naming);
    }
    /* the C verdict on the real source is reported, never assumed */
    {
        Reference direct;
        if(reference_for(source,&direct))fprintf(stderr,"ORACLE_DIRECT %s expressible\n",label);
        else fprintf(stderr,"ORACLE_FREE %s reason=%s\n",label,direct.why);
        reference_free(&direct);
    }
    /* structural expectations that are the producer's own documented stream:
     * the call, the ret, the import, the entry and the REL32 site */
    {
        uint8_t expected_text[16];size_t text_size=0;
        NtX64Operand forward={.kind=NT_X64_REL,.imm=0,.is_signed=1};
        text_size+=encode_(expected_text+text_size,"call",&forward,1);
        text_size+=encode_(expected_text+text_size,"ret",NULL,0);
        CHECKL(text_size==6,"x64 oracle text size",label);
        CHECKL(nova.sections[0].size==6&&!memcmp(nova.sections[0].bytes,expected_text,6),
               "producer .text is the x64 oracle stream",label);
        CHECKL(nova.target==(!strcmp(target,"uefi")?1u:2u),"recorded target",label);
        CHECKL(nova.symbol_count==items+2&&nova.relocation_count==1,"symbol and reloc counts",label);
        /* `main_name` is the C object writer's own name for the twin's main,
         * so the entry check compares the producer against the writer rather
         * than against a spelling.
         *
         * The import symbol is named here by ASKING, and the comment that used
         * to stand here was false. It said the import is "the one name the C
         * writer will NOT agree with ... there is no C answer to copy", and
         * built the expectation from the writer's module prefix plus the local
         * alias. There is a C answer, and it is not that one: the reference
         * names an unresolved import by its PATH. frontend.c:2974 keeps the
         * dotted path in f->import_name and the alias in f->name;
         * codegen.c:1586-1599 splits the path at its last dot and gives the
         * head to add_symbol as the module and the tail as the name;
         * object_build.c:305 joins head, dot and tail. So the declared module
         * and the alias are both discarded, and an expectation built from them
         * agreed with a wrong producer by construction -- which is exactly why
         * the disagreement was invisible here. c_reference_name asks, from the
         * producer source's own import declaration, and the answer is compared
         * with strcmp. */
        /* The expected entry is ASKED of the reference for the producer
         * source's own declarations, never stated. object_build.c:337-351
         * names the entry only for the symbol at image.entry whose function is
         * exported AND whose name is "main", and codegen.c:1557-1562 sets
         * image.entry only for a function that is exported and named main, so
         * the reference answers 0 for a non-exported main, for a module with
         * no main, and for an exported function under any other name.
         *
         * The previous form of this check located the twin's main BY NAME in
         * the produced table and required entry_symbol to equal that index. It
         * could not see a wrong entry for a program whose main the reference
         * does not name, because the index it compared against was derived
         * from the same assumption. Asking removes the assumption. */
        {
            char *naming=naming_source(source,alias);
            uint32_t want_entry=naming?c_reference_entry(naming):UINT32_MAX;
            const NtObjectSymbol *em;
            naming_source_is_the_fixture(source,naming,label);
            CHECKL(want_entry!=UINT32_MAX,
                   "the C reference writes an entry for the producer's own declarations",label);
            CHECKL(want_entry>=1&&want_entry<=nova.symbol_count&&
                   nova.entry_symbol==want_entry,
                   "the produced entry is the one the C reference names",label);
            if(want_entry>=1&&want_entry<=nova.symbol_count){
                em=nova.symbols+want_entry-1;
                /* The symbol the reference names must be an exported .text
                 * function, which is the conjunction object_build.c applies
                 * before it indexes the entry at all. */
                CHECKL(em->section==NT_OBJECT_TEXT&&
                       (em->flags&NT_OBJECT_FUNCTION)&&(em->flags&NT_OBJECT_EXPORT),
                       "the reference's entry names an exported .text function",label);
            }
            free(naming);
        }
        {
            char *main_name=c_name_of(twin,"main");
            uint32_t entry,call=0;
            int have_import=ref_import!=NULL;
            CHECKL(main_name,"C canonical name for the twin's main",label);
            CHECKL(have_import,"C canonical name for the producer source's import",label);
            entry=main_name?index_of(&nova,main_name):0;
            CHECKL(entry!=0&&nova.entry_symbol==entry,
                   "entry symbol is the symbol the C object writer named main",label);
            if(have_import){
                call=index_of(&nova,ref_import);
                CHECKL(call!=0,"the import is in the table under the reference's name",label);
                if(call){
                    const NtObjectSymbol *im=nova.symbols+call-1;
                    CHECKL(im->section==0&&im->offset==0&&im->size==0&&
                           (im->flags&NT_OBJECT_IMPORT)&&!(im->flags&NT_OBJECT_EXPORT),
                           "import symbol is null and not exported",label);
                }
            }
            CHECKL(nova.relocations[0].section==NT_OBJECT_TEXT&&
                   nova.relocations[0].kind==NT_OBJECT_REL32&&
                   nova.relocations[0].offset==1&&nova.relocations[0].target==call&&
                   nova.relocations[0].addend==0,"REL32 targets the import",label);
            free(main_name);
        }
    }
    CHECKL(layout_verdict(label,&nova,twin,detail,sizeof detail),
           "data layout parity with the C frontend pipeline",label);
    {   /* the string table is not a layout field, so the contract text of the
         * produced object is compared with the C object writer here */
        Reference cr;
        memset(&cr,0,sizeof cr);
        if(reference_for(twin,&cr)){
            char *imported=import_probe(target,alias);
            int contracts=contract_verdict_with(label,&nova,&cr.canonical,ref_import,imported);
            free(imported);
            CHECKL(contracts,"contract text parity with the C object writer",label);
        } else CHECKL(0,"C reference for the twin",label);
        reference_free(&cr);
    }
    free(ref_import);
    nt_object_free(&nova);
}

static void simple_case(const NovaHostImage *image,const char *label,const Item *items,
                        size_t count,const char *target,const char *alias){
    char source[SRCROOM],twin[SRCROOM];
    if(build_source(source,sizeof source,items,count,target,alias)>sizeof source||
       build_twin(twin,sizeof twin,items,count,target)>sizeof twin){
        CHECKL(0,"fixture fits its buffer",label);return;
    }
    data_case(image,label,source,twin,target,alias,count);
}

int main(void){
    const char*paths[]={
        "tests/nova/tests/x64-lower-nxo-combined-entry.nova",
        "compiler/nova/backend/x64/x64_lower_nxo.nova","compiler/nova/backend/x64/x64_lower_control.nova",
        "compiler/nova/backend/x64/x64_lower_fixed.nova","compiler/nova/backend/x64/x64_fixed.nova",
        "compiler/nova/analysis/types/register_widths.nova","compiler/nova/formats/nxo/nxo.nova",
        "compiler/nova/formats/pe/pe.nova","compiler/nova/frontend/parser.nova",
        "compiler/nova/frontend/ast.nova","compiler/nova/frontend/lexer.nova"
    ,
        "compiler/nova/macros/macro_splice.nova",
        "compiler/nova/macros/macro_expand.nova",
        "compiler/nova/macros/constant_eval.nova"};
    char*sources[14]={0};NtFInput inputs[14];
    for(unsigned i=0;i<14;i++){size_t n=0;sources[i]=loadf(paths[i],&n);inputs[i]=(NtFInput){paths[i],sources[i],n};}
    int all=1;for(unsigned i=0;i<14;i++)if(!sources[i])all=0;CHECK(all,"sources load");
    NtArtifact artifact={0};int compiled=all&&nova_compile_many_v2(inputs,14,&artifact);
    CHECK(compiled,"Nova modules compile");
    if(!compiled)fprintf(stderr,"E%u %zu:%zu %s\n",artifact.error.code,artifact.error.line,artifact.error.column,artifact.error.message);
    NovaHostImage image={0};CHECK(compiled&&nova_host_map(&artifact,&image),"image maps");
    if(image.memory){
        /* ---- the two retained fixtures: UEFI and bare target, alias zz and aa,
         *      identical declarations, the layout must not depend on either ---- */
        {
            static const Item classic[]={{"zeta",2,4660,2},{"alpha",1,42,2},{"beta",4,2018915346u,3}};
            simple_case(&image,"uefi_alias_zz",classic,3,"uefi","zz");
            simple_case(&image,"bare_alias_aa",classic,3,"none","aa");
        }
        /* ---- one item per width ---- */
        {
            static const Item singles[]={{"only",1,42,2},{"only",2,4660,2},{"only",4,2018915346u,2},
                                         {"only",8,0x1122334455667788ull,2}};
            for(unsigned w=0;w<4;w++){
                char label[32];snprintf(label,sizeof label,"single_u%u",singles[w].width*8);
                simple_case(&image,label,&singles[w],1,"uefi","zz");
            }
        }
        /* ---- the mixed width pairs, forwards and name reversed. The later name
         *      cannot be the import alias, which the producer refuses to share. */
        {
            static const Item pairs[]={
                {"aa",1,0x11,2},{"bb",8,0x2233445566778899ull,2},
                {"aa",8,0x2233445566778899ull,2},{"bb",1,0x11,2},
                {"aa",2,0x1122,2},{"bb",4,0x33445566u,2},
                {"aa",4,0x33445566u,2},{"bb",2,0x1122,2},
                {"yn",1,0x11,2},{"aa",8,0x2233445566778899ull,2},
                {"yn",8,0x2233445566778899ull,2},{"aa",1,0x11,2},
                {"yn",2,0x1122,2},{"aa",4,0x33445566u,2},
                {"yn",4,0x33445566u,2},{"aa",2,0x1122,2}};
            static const char *pair_labels[]={
                "u8_then_u64","u64_then_u8","u16_then_u32","u32_then_u16",
                "reversed_u8_u64","reversed_u64_u8","reversed_u16_u32","reversed_u32_u16"};
            for(unsigned i=0;i<8;i++)simple_case(&image,pair_labels[i],&pairs[i*2],2,"uefi","zz");
        }
        /* ---- all four widths in one section, three declaration orders ---- */
        {
            static const Item up[]={{"a",1,1,2},{"b",2,2,2},{"c",4,3,2},{"d",8,4,2}};
            static const Item down[]={{"d",8,4,2},{"c",4,3,2},{"b",2,2,2},{"a",1,1,2}};
            static const Item swapped[]={{"d",8,4,2},{"b",2,2,2},{"c",4,3,2},{"a",1,1,2}};
            simple_case(&image,"four_widths_ascending",up,4,"uefi","zz");
            simple_case(&image,"four_widths_descending",down,4,"uefi","zz");
            simple_case(&image,"four_widths_mid_swap",swapped,4,"uefi","zz");
        }
        /* ---- every alignment boundary a wider item can land on ---- */
        {
            static const Item pad1[]={{"a",1,1,2},{"z",2,2,2}};
            static const Item pad2[]={{"a",1,1,2},{"b",1,2,2},{"z",4,3,2}};
            static const Item pad3[]={{"a",1,1,2},{"b",1,2,2},{"c",1,3,2},{"z",8,4,2}};
            static const Item pad4[]={{"a",1,1,2},{"b",1,2,2},{"c",1,3,2},{"d",1,4,2},{"z",8,5,2}};
            static const Item pad5[]={{"a",1,1,2},{"b",1,2,2},{"c",1,3,2},{"d",1,4,2},
                                      {"e",1,5,2},{"z",8,6,2}};
            static const Item pad7[]={{"a",1,1,2},{"b",1,2,2},{"c",1,3,2},{"d",1,4,2},
                                      {"e",1,5,2},{"f",1,6,2},{"g",1,7,2},{"z",8,8,2}};
            static const Item pad8[]={{"a",1,1,2},{"b",1,2,2},{"c",1,3,2},{"d",1,4,2},
                                      {"e",1,5,2},{"f",1,6,2},{"g",1,7,2},{"h",1,8,2},{"z",8,9,2}};
            static const Item u16x3[]={{"a",2,1,2},{"b",2,2,2},{"c",2,3,2},{"z",8,4,2}};
            static const Item u16x5[]={{"a",2,1,2},{"b",2,2,2},{"c",2,3,2},{"d",2,4,2},
                                       {"e",2,5,2},{"z",8,6,2}};
            static const Item u32x1[]={{"a",4,1,2},{"z",8,2,2}};
            static const Item u32x3[]={{"a",4,1,2},{"b",4,2,2},{"c",4,3,2},{"z",8,4,2}};
            static const Item u32u8[]={{"a",4,1,2},{"b",1,2,2},{"c",1,3,2},{"d",1,4,2},{"z",8,5,2}};
            static const Item u16u8[]={{"a",2,1,2},{"b",1,2,2},{"z",8,3,2}};
            simple_case(&image,"align2_after_1_u8",pad1,2,"uefi","zz");
            simple_case(&image,"align4_after_2_u8",pad2,3,"uefi","zz");
            simple_case(&image,"align8_after_3_u8",pad3,4,"uefi","zz");
            simple_case(&image,"align8_after_4_u8",pad4,5,"uefi","zz");
            simple_case(&image,"align8_after_5_u8",pad5,6,"uefi","zz");
            simple_case(&image,"align8_after_7_u8",pad7,8,"uefi","zz");
            simple_case(&image,"align8_at_8_u8",pad8,9,"uefi","zz");
            simple_case(&image,"align8_after_3_u16",u16x3,4,"uefi","zz");
            simple_case(&image,"align8_after_5_u16",u16x5,6,"uefi","zz");
            simple_case(&image,"align8_after_1_u32",u32x1,2,"uefi","zz");
            simple_case(&image,"align8_after_3_u32",u32x3,4,"uefi","zz");
            simple_case(&image,"align8_after_u32_3_u8",u32u8,5,"uefi","zz");
            simple_case(&image,"align8_after_u16_u8",u16u8,3,"uefi","zz");
        }
        /* ---- byte order, not locale or declaration order ---- */
        {
            static const Item ascii[]={{"Z",1,1,2},{"_x",4,2,2},{"abc",2,3,2},{"a",8,4,2}};
            static const Item digits[]={{"e0",1,1,2},{"d0",8,2,2},{"d00",2,3,2},{"a0",4,4,2}};
            static const Item prefix[]={{"ab",8,1,2},{"a",1,2,2},{"abc",2,3,2},{"b",4,4,2}};
            static const Item mixedcase[]={{"aB",1,1,2},{"Ab",2,2,2},{"AB",4,3,2},{"a",8,4,2}};
            simple_case(&image,"byte_order_mixed",ascii,4,"uefi","zz");
            simple_case(&image,"byte_order_digits",digits,4,"uefi","zz");
            simple_case(&image,"byte_order_prefix",prefix,4,"uefi","zz");
            simple_case(&image,"byte_order_case",mixedcase,4,"uefi","zz");
        }
        /* ---- both sections at once, and the alias must not move a byte ---- */
        {
            static const Item two[]={{"zeta",2,4660,2},{"alpha",1,42,2},{"beta",4,2018915346u,3}};
            static const Item split[]={{"zeta",8,4660,2},{"alpha",1,42,3},{"beta",2,7,3}};
            static const Item interleave[]={{"m1",1,1,2},{"m2",8,2,3},{"m3",2,3,2},{"m4",4,4,3}};
            simple_case(&image,"two_sections_classic",two,3,"uefi","zz");
            simple_case(&image,"two_sections_split",split,3,"uefi","zz");
            simple_case(&image,"two_sections_interleaved",interleave,4,"uefi","zz");
            /* the same declarations under a different alias and a different
             * target: the import is not data and must not move an offset */
            simple_case(&image,"alias_and_target_independent",two,3,"none","aa");
        }
        /* ---- the 1..64 item sweep, mixed widths, ascending names ---- */
        {
            Item sweep[MAX_ITEMS];
            char names[MAX_ITEMS][8];
            size_t i;
            for(i=0;i<MAX_ITEMS;i++){
                static const unsigned widths[4]={1,2,4,8};
                snprintf(names[i],sizeof names[i],"d%02zu",i);
                sweep[i]=(Item){names[i],widths[i%4],(uint64_t)(i*3+1),2};
            }
            for(i=1;i<=MAX_ITEMS;i++){
                char label[32],source[SRCROOM],twin[SRCROOM];
                snprintf(label,sizeof label,"sweep_%zu",i);
                if(build_source(source,sizeof source,sweep,i,"uefi","zz")>sizeof source||
                   build_twin(twin,sizeof twin,sweep,i,"uefi")>sizeof twin){
                    CHECKL(0,"sweep fixture fits",label);break;
                }
                data_case(&image,label,source,twin,"uefi","zz",i);
            }
        }
        /* ---- the declaration index tiebreak of the name order is unreachable:
         *      both producers refuse two data items of the same name, so no
         *      equal name can ever reach the comparator. Asserted, not assumed. */
        {
            const char *twin_dup="module m\ntarget x86_64-nexora-uefi\nsection .rdata {\n"
                "data aa:u8=1\ndata aa:u8=2\n}\n"
                "section .text {\nexport fn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
            Reference dup;
            int refused=!reference_for(twin_dup,&dup);
            if(!refused)reference_free(&dup);
            CHECKL(refused,"C frontend refuses two data items of one name","tie_break_unreachable");
            CHECKL(refused&&strstr(dup.why,"duplicate")!=NULL,
                   "C frontend names the duplicate diagnostic","tie_break_unreachable");
        }
        /* ---- the retained refusals ---- */
        {
        static const Item classic[]={{"zeta",2,4660,2},{"alpha",1,42,2},{"beta",4,2018915346u,3}};
        char source[SRCROOM],twin[SRCROOM];
        if(build_source(source,sizeof source,classic,3,"uefi","zz")>sizeof source||
           build_twin(twin,sizeof twin,classic,3,"uefi")>sizeof twin)
            CHECK(0,"retained refusal fixtures bounded");
        else{
            char missing[SRCROOM],arity[SRCROOM],range[SRCROOM];
            if(snprintf(missing,sizeof missing,"%s",source)>=(int)sizeof missing||
               snprintf(arity,sizeof arity,"%s",source)>=(int)sizeof arity||
               snprintf(range,sizeof range,"%s",source)>=(int)sizeof range)CHECK(0,"copy bounded");
            else{
                char *at;
                at=strstr(missing,"call zz()");if(at)memcpy(at,"call bad()",10);
                at=strstr(arity,"call zz()");if(at)memcpy(at,"call zz(1)",10);
                at=strstr(range,"alpha:u8=42");if(at)memcpy(at,"alpha:u8=256",12);
                CHECK(strstr(missing,"call bad()")&&strstr(arity,"call zz(1)")&&
                      strstr(range,"alpha:u8=256"),"retained refusal fixtures edited");
                rejected(&image,missing,2048,800,"missing alias transactional");
                rejected(&image,arity,2048,800,"arity transactional");
                rejected(&image,range,2048,800,"data range transactional");
                rejected(&image,source,128,800,"short output transactional");
            }
        }
        }
    }
    if(image.memory)nova_host_unmap(&image);
    if(compiled)nt_artifact_free(&artifact);
    for(unsigned i=0;i<14;i++)free(sources[i]);

    /* ---- the contract oracle: the varied contract text of the C object
     *      writer, through the C reader and through the Nova accessor ---- */
    {
        NovaHostImage accessor = {0};
        NtArtifact accessor_artifact = {0};
        if (contract_image(&accessor, &accessor_artifact)) contract_suite(&accessor);
        if (accessor.memory) nova_host_unmap(&accessor);
        nt_artifact_free(&accessor_artifact);
    }
printf("NTASM_NOVA_X64_LOWER_NXO_COMBINED checks=%u failures=%u cases=%u\n",checks,failures,cases);
    return failures?1:0;
}
