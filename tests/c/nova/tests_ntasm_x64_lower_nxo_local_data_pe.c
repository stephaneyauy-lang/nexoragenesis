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

/* NXO to PE adapters of the local call/ret producer, measured against the real C
 * pipeline.
 *
 * This gate used to build its expectation by hand: an NtObject whose .rdata was
 * the three bytes 34 12 2a with alpha at offset 2, then nt_object_write,
 * nt_object_materialize and nt_make_pe over it. That golden encodes the
 * pre-spec layout, items packed back to back in declaration order, and
 * nt_object_write is a pure serialiser, so it copied whatever the caller handed
 * it and the gate confirmed whatever the producer emitted. Here the drift even
 * survived the NXO comparison, because the PE carries the same wrong bytes.
 *
 * The data half of the expectation now comes from the C frontend and codegen,
 * nt_frontend_compile_object + nt_codegen_x64_object + nt_object_write, which
 * lays items out by ascending byte-wise unsigned name and aligns each one to
 * min(width,8) exactly as spec/formats/nxo-v0.md requires. The .text half stays the
 * producer's own documented instruction stream, encoded by nt_x64_encode, the C
 * x64 oracle: build_local_data_core emits a bare call/ret stream and the C
 * frontend refuses that body (503), so no C parity is claimed for it. The
 * assembled object is cross checked field by field against the data half of
 * nt_object_compile, the canonical builder of the same C frontend, so the
 * expectation is proven to carry the canonical layout rather than asserted to.
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
static uint64_t run(const NovaHostImage*i,const char*source,uint8_t*out,size_t cap){
    NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"context init");
    uint64_t sh=nova_borrow_v2(&c,(void*)source,strlen(source),0),oh=nova_borrow_v2(&c,out,cap,1);
    uint64_t args[]={sh,strlen(source),oh,cap};uint64_t code=i->entry(&c,args,4);
    if(c.error)fprintf(stderr,"Nova runtime error=%llu source=%llu offset=%llu\n",(unsigned long long)c.error,(unsigned long long)c.error_source,(unsigned long long)c.error_offset);
    CHECK(c.error==0,"runtime clean");CHECK(nova_context_destroy_v2(&c),"context cleanup");cases++;return code;
}
static void rejected(const NovaHostImage*i,const char*source,size_t cap,uint64_t expected,const char*label){
    uint8_t out[65536];memset(out,0xcc,sizeof out);uint64_t code=run(i,source,out,cap);int intact=code==expected;
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

/* The whole table, then the distinctness sweep. */
static void contract_suite(const NovaHostImage *ci)
{
    unsigned k;
    for (k = 0; k < CONTRACT_PROBE_COUNT; k++) contract_round_trip(ci, contract_probes + k);
    contract_distinct();
    cases++;
}

/* The same comparison, for an object whose symbol table carries one symbol the
 * canonical twin does not declare. `extra_name` and `extra_contract` supply the
 * C text for that one symbol, so the helper of a local fixture is measured
 * against the C object writer and not against a literal. */
static int contract_verdict_with(const char *label, const NtObject *o, const NtObject *canon,
                                 const char *extra_name, const char *extra_contract)
{
    size_t j;
    int same = 1;
    for (j = 0; o->symbols && j < o->symbol_count; j++) {
        const char *want = NULL;
        /* `extra_name` is a bare fixture name and the symbol it stands for now
         * carries the C writer's module qualified spelling, so the two are
         * matched on the tail. The contract text itself holds no module name,
         * which is why the tail is the whole of the identity here. */
        if (extra_name && !strcmp(contract_tail(o->symbols[j].name), extra_name))
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

/* The local fixtures declare two functions, main and helper. The C expressible
 * twin this harness measures against declares main only, so the helper text is
 * read from a module carrying exactly the helper declaration and the same
 * target. contract_text reads no body text and no export flag, so that is the
 * contract of the helper the producer writes; the bytes still come from the C
 * object writer. Its module is the PRODUCER's own, `m`, because the C object
 * writer qualifies every symbol name with the module of the source it was
 * given (object_build.c nt_object_compile): under any other module this probe
 * would answer with a name the producer's table never carries, and the NXO
 * byte comparison below would then be comparing two different tables. */
static const char *const LOCAL_HELPER_PROBE =
    "module m\ntarget x86_64-nexora-uefi\nsection .text {\n"
    "fn helper()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
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

static int assemble(const NtCodeImage *image,const NtObject *canon,const char *main_contract,
                    const char *helper_contract,Assembly *a,char *why,size_t cap){
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
        symbols[j].contract=!strcmp(s->name,"helper")?(char*)helper_contract:
            !strcmp(s->name,"main")?(char*)main_contract:
            (char*)c_symbol_contract(canon,contract_tail(s->name));
        if(!symbols[j].contract){
            free(symbols);free(relocs);free(names);free(order);
            snprintf(why,cap,"assembly: the C object writer has no contract for %s",
                     s->name);return 0;}
        symbols[j].section=s->section;symbols[j].offset=s->offset;symbols[j].size=s->size;
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
        a->object.symbols[j]=symbols[order[j].index];
        if(symbols[order[j].index].section==NT_OBJECT_TEXT&&
           (symbols[order[j].index].flags&NT_OBJECT_EXPORT)&&
           (symbols[order[j].index].flags&NT_OBJECT_FUNCTION))
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

typedef struct { int ok; NtBuffer file; NtObject canonical; char why[256];
               char *main_contract,*helper_contract;
               /* the SAME two symbols, named rather than described: the C
                * object writer qualifies every name with the module of the
                * source it was given, so the spelling the producer's table
                * must carry is the writer's own answer and not a literal. main
                * comes out of the twin, helper out of the helper probe. */
               char *main_name,*helper_name; } Reference;
static void reference_free(Reference *r){free(r->file.bytes);r->file.bytes=NULL;
    if(r->canonical.symbols)nt_object_free(&r->canonical);
    free(r->main_contract);r->main_contract=NULL;
    free(r->helper_contract);r->helper_contract=NULL;
    free(r->main_name);r->main_name=NULL;
    free(r->helper_name);r->helper_name=NULL;
    r->ok=0;}

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
    /* main is declared by the twin, helper is not: both texts and both NAMES
     * come from the C object writer, main out of the twin and helper out of the
     * declaration the producer source carries. A refusal of either is a refusal
     * of the oracle, not a reason to fall back on a spelling. */
    ref->main_contract=c_contract_of(&ref->canonical,"main");
    ref->helper_contract=c_contract(LOCAL_HELPER_PROBE,"helper");
    ref->main_name=c_name_of(source,"main");
    ref->helper_name=c_name_of(LOCAL_HELPER_PROBE,"helper");
    if(!ref->main_contract||!ref->helper_contract||!ref->main_name||!ref->helper_name){
        snprintf(ref->why,sizeof ref->why,
                 "nt_object_compile: no contract or name for main or helper");
        free(ref->main_contract);ref->main_contract=NULL;
        free(ref->helper_contract);ref->helper_contract=NULL;
        free(ref->main_name);ref->main_name=NULL;
        free(ref->helper_name);ref->helper_name=NULL;
        nt_object_free(&ref->canonical);return 0;
    }
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
    if(!assemble(&image,&ref->canonical,ref->main_contract,ref->helper_contract,
                 &assembly,ref->why,sizeof ref->why)){
        nt_code_image_free(&image);nt_frontend_free(&program);return 0;
    }
    if(!nt_object_write(&assembly.object,&ref->file,&error)){
        snprintf(ref->why,sizeof ref->why,"nt_object_write %u %s",error.code,error.message);
        assembly_free(&assembly);nt_code_image_free(&image);nt_frontend_free(&program);return 0;
    }
    assembly_free(&assembly);nt_code_image_free(&image);nt_frontend_free(&program);
    for(k=0;k<ref->canonical.symbol_count;k++)
        if((ref->canonical.symbols[k].flags&(NT_OBJECT_EXPORT|NT_OBJECT_FUNCTION))==
           (NT_OBJECT_EXPORT|NT_OBJECT_FUNCTION)&&ref->canonical.symbols[k].section==NT_OBJECT_TEXT)
            canonical_entry=(uint32_t)k+1;
    if(!canonical_entry){
        snprintf(ref->why,sizeof ref->why,"nt_object_compile: no exported .text function");
        free(ref->file.bytes);ref->file.bytes=NULL;nt_object_free(&ref->canonical);return 0;
    }
    ref->ok=1;
    return 1;
}

static int is_data(const NtObjectSymbol *s){return s->section==NT_OBJECT_RDATA||s->section==NT_OBJECT_DATA;}

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
static int data_symbols_match(const NtObject *a,const NtObject *b,int by_tail,char *detail,size_t room){
    size_t j,k,da=0,db=0;
    detail[0]=0;
    for(j=0;j<a->symbol_count;j++)if(is_data(a->symbols+j))da++;
    for(j=0;j<b->symbol_count;j++)if(is_data(b->symbols+j))db++;
    if(da!=db){snprintf(detail,room,"data symbol count %zu vs %zu",da,db);return 0;}
    for(j=0;j<a->symbol_count;j++){
        if(!is_data(a->symbols+j))continue;
        for(k=0;k<b->symbol_count;k++){
            const char *an=a->symbols[j].name,*bn=b->symbols[k].name;
            if(!is_data(b->symbols+k))continue;
            if(by_tail){an=tail_of(an);bn=tail_of(bn);}
            if(strcmp(an,bn))continue;
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
         data_symbols_match(nova,&cref,0,detail,room)&&detail[0]==0;
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
 * The expected object: canonical data, x64 oracle code stream
 * ------------------------------------------------------------------ */

typedef struct {
    NtObject object;
    uint8_t *text,*rdata,*data;
    size_t text_size;
    NtObjectSymbol *symbols,*sorted;
    NtObjectReloc *reloc;
    char (*names)[64];
    NameOrder *order;
} Expected;

static void expected_free(Expected *e){
    free(e->text);free(e->rdata);free(e->data);free(e->symbols);free(e->sorted);
    free(e->reloc);free(e->names);free(e->order);
    memset(e,0,sizeof *e);
}

/* Every data byte and every data symbol field is copied from the canonical C
 * object; the .text stream, the two function offsets and the REL32 site are the
 * producer's own documented stream, encoded by nt_x64_encode. The NAMES are the
 * C object writer's own: the data names are copied straight out of `canon`, and
 * the two function names arrive as `main_name` and `helper_name`, which the
 * caller obtained from the writer. That is what makes object.c's strict
 * ascending table the same table the producer builds, since a common module
 * prefix does not change the relative order of two names.
 * Returns 0 on allocation failure or when the C table is not the expected shape. */
static int expected_build(const NtObject *canon,const char *main_contract,
                          const char *helper_contract,const char *main_name,
                          const char *helper_name,int helper_first,Expected *e){
    size_t data_symbols=0,j,used=0;
    NtX64Operand forward={.kind=NT_X64_REL,.imm=0,.is_signed=1};
    memset(e,0,sizeof *e);
    for(j=0;j<canon->symbol_count;j++)if(is_data(canon->symbols+j))data_symbols++;
    e->text=calloc(8,1);
    e->reloc=calloc(1,sizeof *e->reloc);
    e->symbols=calloc(data_symbols+2,sizeof *e->symbols);
    e->names=calloc(data_symbols+2,sizeof *e->names);
    e->order=calloc(data_symbols+2,sizeof *e->order);
    e->rdata=calloc(canon->sections[1].size?canon->sections[1].size:1,1);
    e->data=calloc(canon->sections[2].size?canon->sections[2].size:1,1);
    if(!e->text||!e->reloc||!e->symbols||!e->names||!e->order||!e->rdata||!e->data){
        expected_free(e);return 0;
    }
    if(canon->sections[1].size)memcpy(e->rdata,canon->sections[1].bytes,canon->sections[1].size);
    if(canon->sections[2].size)memcpy(e->data,canon->sections[2].bytes,canon->sections[2].size);
    /* the documented stream: helper first is ret,call,ret, otherwise call,ret,ret */
    if(helper_first)e->text_size+=encode_(e->text+e->text_size,"ret",NULL,0);
    e->text_size+=encode_(e->text+e->text_size,"call",&forward,1);
    e->text_size+=encode_(e->text+e->text_size,"ret",NULL,0);
    if(!helper_first)e->text_size+=encode_(e->text+e->text_size,"ret",NULL,0);
    for(j=0;j<canon->symbol_count;j++){
        const NtObjectSymbol *c=canon->symbols+j;
        int n;
        if(!is_data(c))continue;
        n=snprintf(e->names[used],sizeof e->names[used],"%s",c->name);
        if(n<=0||(size_t)n>=sizeof e->names[used]){expected_free(e);return 0;}
        e->symbols[used]=(NtObjectSymbol){e->names[used],(char*)c->contract,c->section,c->flags,c->offset,c->size};
        e->order[used].name=e->names[used];e->order[used].index=used;
        used++;
    }
    {
        uint64_t helper_at=helper_first?0:6,main_at=helper_first?1:0;
        int n;
        n=snprintf(e->names[used],sizeof e->names[used],"%s",helper_name);
        if(n<=0||(size_t)n>=sizeof e->names[used]){expected_free(e);return 0;}
        e->symbols[used]=(NtObjectSymbol){e->names[used],(char*)helper_contract,NT_OBJECT_TEXT,
                                          NT_OBJECT_FUNCTION,helper_at,1};
        e->order[used].name=e->names[used];e->order[used].index=used;used++;
        n=snprintf(e->names[used],sizeof e->names[used],"%s",main_name);
        if(n<=0||(size_t)n>=sizeof e->names[used]){expected_free(e);return 0;}
        e->symbols[used]=(NtObjectSymbol){e->names[used],(char*)main_contract,NT_OBJECT_TEXT,
                                          NT_OBJECT_FUNCTION|NT_OBJECT_EXPORT,main_at,6};
        e->order[used].name=e->names[used];e->order[used].index=used;used++;
    }
    /* the table object.c is given: strictly ascending by name, entry indexed in
     * the sorted table, the REL32 pointing at the sorted index of helper */
    {
        NtObjectSymbol *sorted=calloc(used,sizeof *sorted);
        if(!sorted){expected_free(e);return 0;}
        e->sorted=sorted;
        qsort(e->order,used,sizeof *e->order,name_compare);
        /* named fields: NtObjectReloc orders target before offset */
        e->reloc[0].section=NT_OBJECT_TEXT;
        e->reloc[0].kind=NT_OBJECT_REL32;
        e->reloc[0].offset=helper_first?2u:1u;
        e->reloc[0].addend=0;
        for(j=0;j<used;j++){
            sorted[j]=e->symbols[e->order[j].index];
            if(!strcmp(sorted[j].name,main_name))e->object.entry_symbol=(uint32_t)j+1;
            if(!strcmp(sorted[j].name,helper_name))e->reloc[0].target=(uint32_t)j+1;
        }
        if(!e->object.entry_symbol||!e->reloc[0].target){free(sorted);expected_free(e);return 0;}
        e->object.target=1;
        e->object.symbols=sorted;
        e->object.symbol_count=used;
        e->object.relocations=e->reloc;
        e->object.relocation_count=1;
        e->object.sections[0]=(NtBuffer){e->text,e->text_size,e->text_size};
        e->object.sections[1]=(NtBuffer){e->rdata,canon->sections[1].size,canon->sections[1].size};
        e->object.sections[2]=(NtBuffer){e->data,canon->sections[2].size,canon->sections[2].size};
    }
    /* the hand assembly must carry the canonical C data half, proven here and
     * not asserted: the same payload bytes and the same symbol fields as the
     * nt_object_compile object this expectation was derived from */
    {
        char detail[256];
        detail[0]=0;
        if(e->object.sections[1].size!=canon->sections[1].size||
           e->object.sections[2].size!=canon->sections[2].size||
           first_data_byte(&e->object,canon)>=0||
           !data_symbols_match(&e->object,canon,1,detail,sizeof detail)||detail[0]){
            fprintf(stderr,"expected_build reason ro=%zu/%zu data=%zu/%zu first=%ld %s\n",
                    e->object.sections[1].size,canon->sections[1].size,
                    e->object.sections[2].size,canon->sections[2].size,
                    first_data_byte(&e->object,canon),detail);
            expected_free(e);return 0;
        }
    }
    return 1;
}

/* ------------------------------------------------------------------ *
 * Fixtures
 * ------------------------------------------------------------------ */

/* section 2 is .rdata, section 3 is .data, width is in bytes. */
typedef struct { const char *name; unsigned width; uint64_t value; unsigned section; int exported; } Item;

#define MAX_ITEMS 64
#define SRCROOM 32768
#define BODY_C "export fn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n"
/* WHY BODY_N_* CARRY `export fn main`. The reference sets NT_OBJECT_EXPORT from
 * the declaration's own `exported` bit (object_build.c:317) and names the entry
 * only for an EXPORTED main (object_build.c:343-347, codegen.c:1557-1562), so a
 * main without the modifier is a legal object with entry_symbol = 0 and flags =
 * NT_OBJECT_FUNCTION alone. The C reference REFUSES this body (a bare ret has no
 * available stack/frame balance proof: 503), so the oracle is BODY_C above, the
 * export fn main / return 0 twin, and producer and twin must declare the SAME
 * program. The producer used to hardcode the export bit on main, which made the
 * two agree in the output even though they declared different programs; that
 * was hiding the difference, not proving layout parity. The twin is what the
 * reference is asked about, so it is the producer fixture that moves. */
#define BODY_N_MAIN_FIRST "export fn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nret\n}\n" \
                          "fn helper()->u64\neffects {}\nclobbers {} {\nret\n}\n"
#define BODY_N_HELPER_FIRST "fn helper()->u64\neffects {}\nclobbers {} {\nret\n}\n" \
                            "export fn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nret\n}\n"

static size_t emit_items(char *dst,size_t room,const Item *items,size_t count){
    size_t used=0,i;
    for(i=0;i<count;i++){
        int n=snprintf(dst+used,room-used,"%sdata %s:u%u=%llu\n",items[i].exported?"export ":"",
                       items[i].name,items[i].width*8,(unsigned long long)items[i].value);
        if(n<0||(size_t)n>=room-used)return room+1;
        used+=(size_t)n;
    }
    return used;
}
static size_t build_source(char *dst,size_t room,const Item *items,size_t count,
                           const char *body,int text_first){
    static const char *const order[2][3]={{".rdata",".data",".text"},
                                          {".text",".data",".rdata"}};
    size_t used=(size_t)snprintf(dst,room,"module m\ntarget x86_64-nexora-uefi\n");
    unsigned k;
    size_t i;
    int n;
    if(used>=room)return room+1;
    for(k=0;k<3;k++){
        const char *name=order[text_first][k];
        unsigned want=name[1]=='r'?2u:3u;
        n=snprintf(dst+used,room-used,"section %s {\n",name);
        if(n<0||(size_t)n>=room-used)return room+1;
        used+=(size_t)n;
        if(name[1]=='t'){
            n=snprintf(dst+used,room-used,"%s",body);
            if(n<0||(size_t)n>=room-used)return room+1;
            used+=(size_t)n;
        }else{
            for(i=0;i<count;i++)if(items[i].section==want){
                size_t k2=emit_items(dst+used,room-used,&items[i],1);
                if(k2>=room-used)return room+1;
                used+=k2;
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

static void free_artifact(NtArtifact *a){
    if(a->pe.bytes){free(a->pe.bytes);a->pe.bytes=NULL;}
    if(a->text.bytes){free(a->text.bytes);a->text.bytes=NULL;}
    if(a->rdata.bytes){free(a->rdata.bytes);a->rdata.bytes=NULL;}
    if(a->data.bytes){free(a->data.bytes);a->data.bytes=NULL;}
    free(a->base_relocations);
    memset(a,0,sizeof *a);
}

/* Runs one fixture through the producer, builds the expectation from the C
 * pipeline and the x64 oracle, and compares the NXO and the PE byte for byte. */
static void pe_case(const NovaHostImage *image,const char *label,const char *source,
                    const char *twin,int helper_first){
    uint8_t out[65536];
    uint64_t code,nxo_size,pe_size;
    NtObject nova={0};
    NtDiagnostic error={0};
    Reference ref;
    Expected expected;
    char detail[512];
    memset(out,0xcc,sizeof out);
    code=run(image,source,out,sizeof out);
    nxo_size=r64(out);pe_size=r64(out+8);
    CHECKL(code==0,"producer accepts the fixture",label);
    if(code!=0){fprintf(stderr,"PE %s producer code=%llu\n",label,(unsigned long long)code);return;}
    CHECKL(nxo_size<=sizeof out-16&&pe_size<=sizeof out-16-nxo_size,"output fits",label);
    if(nxo_size>sizeof out-16||pe_size>sizeof out-16-nxo_size)return;
    CHECKL(nt_object_read(out+16,(size_t)nxo_size,&nova,&error),"C NXO read",label);
    CHECKL(nt_object_validate(&nova,&error),"C NXO validate",label);
    /* the C verdict on the real source is reported, never assumed */
    {
        Reference direct;
        if(reference_for(source,&direct))fprintf(stderr,"ORACLE_DIRECT %s expressible\n",label);
        else fprintf(stderr,"ORACLE_FREE %s reason=%s\n",label,direct.why);
        reference_free(&direct);
    }
    /* the data layout of the produced object, straight against the C pipeline */
    detail[0]=0;
    CHECKL(layout_verdict(label,&nova,twin,detail,sizeof detail),
           "data layout parity with the C frontend pipeline",label);
    {   /* the string table is not a layout field, so the contract text of the
         * produced object is compared with the C object writer here */
        Reference cr;
        memset(&cr,0,sizeof cr);
        if(reference_for(twin,&cr))
            CHECKL(contract_verdict_with(label,&nova,&cr.canonical,"helper",cr.helper_contract),
                   "contract text parity with the C object writer",label);
        else CHECKL(0,"C reference for the twin",label);
        reference_free(&cr);
    }
    /* the canonical C object of the twin is the source of the expectation */
    memset(&ref,0,sizeof ref);
    if(!reference_for(twin,&ref)){
        CHECKL(0,"C reference for the twin",label);
        fprintf(stderr,"PE %s reference reason=%s\n",label,ref.why);
        reference_free(&ref);nt_object_free(&nova);return;
    }
    memset(&expected,0,sizeof expected);
    if(!expected_build(&ref.canonical,ref.main_contract,ref.helper_contract,
                       ref.main_name,ref.helper_name,helper_first,&expected)){
        CHECKL(0,"expected object carries the canonical C data half",label);
        reference_free(&ref);nt_object_free(&nova);return;
    }
    CHECKL(1,"expected object carries the canonical C data half",label);
    {
        NtBuffer expected_nxo={0};
        NtArtifact expected_pe={0};
        CHECKL(nt_object_write(&expected.object,&expected_nxo,&error),"C NXO writer",label);
        CHECKL(nt_object_materialize(&expected.object,&expected_pe,&error),"C materialize",label);
        CHECKL(nt_make_pe(&expected_pe),"C PE writer",label);
        if(code==0&&expected_nxo.bytes){
            CHECKL(nxo_size==expected_nxo.size&&!memcmp(out+16,expected_nxo.bytes,expected_nxo.size),
                   "NXO byte parity",label);
            if(nxo_size!=expected_nxo.size||memcmp(out+16,expected_nxo.bytes,expected_nxo.size)){
                size_t lim=nxo_size<expected_nxo.size?(size_t)nxo_size:expected_nxo.size,off=0;
                while(off<lim&&out[16+off]==expected_nxo.bytes[off])off++;
                fprintf(stderr,"NXO mismatch at=%zu actual=%u expected=%u\n",off,
                        off<nxo_size?out[16+off]:0,off<expected_nxo.size?expected_nxo.bytes[off]:0);
            }
        }
        if(expected_pe.pe.bytes){
            CHECKL(pe_size==expected_pe.pe.size&&
                   !memcmp(out+16+nxo_size,expected_pe.pe.bytes,expected_pe.pe.size),
                   "PE byte parity",label);
            if(pe_size!=expected_pe.pe.size||
               memcmp(out+16+nxo_size,expected_pe.pe.bytes,expected_pe.pe.size)){
                size_t lim=pe_size<expected_pe.pe.size?(size_t)pe_size:expected_pe.pe.size,off=0;
                while(off<lim&&out[16+nxo_size+off]==expected_pe.pe.bytes[off])off++;
                fprintf(stderr,"PE mismatch at=%zu actual=%u expected=%u\n",off,
                        off<pe_size?out[16+nxo_size+off]:0,
                        off<expected_pe.pe.size?expected_pe.pe.bytes[off]:0);
            }
        }
        /* the materialized data sections are the canonical payload, unchanged */
        if(expected_pe.rdata.bytes||expected_pe.rdata.size==0)
            CHECKL(expected_pe.rdata.size==ref.canonical.sections[1].size&&
                   (ref.canonical.sections[1].size==0||
                    !memcmp(expected_pe.rdata.bytes,ref.canonical.sections[1].bytes,
                            ref.canonical.sections[1].size)),"materialized .rdata is the canonical payload",label);
        if(expected_pe.data.bytes||expected_pe.data.size==0)
            CHECKL(expected_pe.data.size==ref.canonical.sections[2].size&&
                   (ref.canonical.sections[2].size==0||
                    !memcmp(expected_pe.data.bytes,ref.canonical.sections[2].bytes,
                            ref.canonical.sections[2].size)),"materialized .data is the canonical payload",label);
        /* the producer's own documented code stream survives materialization */
        {
            uint64_t site=helper_first?2:1;
            CHECKL(expected_pe.text.size==7&&expected_pe.text.bytes[site-1]==0xe8&&
                   expected_pe.text.bytes[site]==(helper_first?0xfa:1)&&
                   expected_pe.text.bytes[site+1]==(helper_first?0xff:0),"patched local REL32",label);
            CHECKL(expected_pe.entry==(helper_first?1:0),"entry matches main position",label);
        }
        free(expected_nxo.bytes);
        free_artifact(&expected_pe);
    }
    expected_free(&expected);
    reference_free(&ref);
    nt_object_free(&nova);
}

static void simple_case(const NovaHostImage *image,const char *label,const Item *items,
                        size_t count,int text_first){
    char source[SRCROOM],twin[SRCROOM];
    const char *body=text_first?BODY_N_HELPER_FIRST:BODY_N_MAIN_FIRST;
    if(build_source(source,sizeof source,items,count,body,text_first)>sizeof source||
       build_source(twin,sizeof twin,items,count,BODY_C,0)>sizeof twin){
        CHECKL(0,"fixture fits its buffer",label);return;
    }
    pe_case(image,label,source,twin,text_first);
}
/* The canonical payload of the classic fixture, spelled out so a reader can
 * check it by hand against spec/formats/nxo-v0.md: alpha sorts before zeta, alpha is one
 * byte at 0, zeta is two bytes aligned to 2 so it lands at 2, .rdata is four
 * bytes, .data is untouched. The C oracle in layout_verdict is what proves these
 * values; this block only restates them. */
static void classic_payload(const NovaHostImage *image,const Item *items){
    char source[SRCROOM];
    uint8_t out[65536];
    uint64_t code,size;
    NtObject nova={0};
    NtDiagnostic error={0};
    if(build_source(source,sizeof source,items,3,BODY_N_MAIN_FIRST,0)>sizeof source){
        CHECK(0,"classic payload fixture bounded");return;
    }
    memset(out,0xcc,sizeof out);
    code=run(image,source,out,sizeof out);
    size=r64(out);
    /* this entry writes put64(nxo_size), put64(pe_size), the NXO, then the PE */
    CHECK(code==0&&size<=sizeof out-16&&nt_object_read(out+16,(size_t)size,&nova,&error)&&
          nt_object_validate(&nova,&error),"classic payload readback");
    if(code!=0||size>sizeof out-16||!nova.symbols)return;
    CHECK(nova.sections[1].size==4&&nova.sections[1].bytes[0]==42&&
          nova.sections[1].bytes[1]==0&&nova.sections[1].bytes[2]==0x34&&
          nova.sections[1].bytes[3]==0x12,"canonical .rdata is 2a 00 34 12");
    CHECK(nova.sections[2].size==4&&!memcmp(nova.sections[2].bytes,"\x12\x34\x56\x78",4),
          "unchanged .data is 12 34 56 78");
    {
        /* The three data symbol names are the C object writer's own answers
         * for the twin of this very fixture, which declares the same items
         * under the same module. Spelling the qualified name out here would
         * pin a bare name in new clothing: it would survive a producer that
         * stopped qualifying, and it would not notice a module change. */
        char twin[SRCROOM];
        char *alpha_name=NULL,*zeta_name=NULL,*beta_name=NULL;
        uint32_t alpha=0,zeta=0,beta=0;size_t k;
        if(build_source(twin,sizeof twin,items,3,BODY_C,0)<=sizeof twin){
            alpha_name=c_name_of(twin,"alpha");
            zeta_name=c_name_of(twin,"zeta");
            beta_name=c_name_of(twin,"beta");
        }
        CHECK(alpha_name&&zeta_name&&beta_name,
              "C canonical names for the classic fixture's data symbols");
        for(k=0;k<nova.symbol_count;k++){
            if(alpha_name&&!strcmp(nova.symbols[k].name,alpha_name))alpha=(uint32_t)k+1;
            if(zeta_name&&!strcmp(nova.symbols[k].name,zeta_name))zeta=(uint32_t)k+1;
            if(beta_name&&!strcmp(nova.symbols[k].name,beta_name))beta=(uint32_t)k+1;
        }
        CHECK(alpha&&zeta&&beta&&nova.symbols[alpha-1].offset==0&&
              nova.symbols[alpha-1].size==1&&nova.symbols[zeta-1].offset==2&&
              nova.symbols[zeta-1].size==2&&nova.symbols[beta-1].offset==0&&
              nova.symbols[beta-1].size==4,"canonical offsets alpha@0 zeta@2 beta@0");
        free(alpha_name);free(zeta_name);free(beta_name);
    }
    nt_object_free(&nova);
}

int main(void){
    const char*paths[]={
        "tests/nova/tests/x64-lower-nxo-local-data-pe-entry.nova",
        "compiler/nova/backend/x64/x64_lower_nxo_pe.nova","compiler/nova/backend/x64/x64_lower_nxo.nova",
        "compiler/nova/backend/x64/x64_lower_control.nova","compiler/nova/backend/x64/x64_lower_fixed.nova",
        "compiler/nova/backend/x64/x64_fixed.nova","compiler/nova/analysis/types/register_widths.nova",
        "compiler/nova/formats/nxo/nxo_link_pe.nova","compiler/nova/formats/nxo/nxo_merge.nova",
        "compiler/nova/formats/nxo/nxo_pe.nova","compiler/nova/formats/nxo/nxo.nova",
        "compiler/nova/formats/pe/pe.nova","compiler/nova/frontend/parser.nova",
        "compiler/nova/frontend/ast.nova","compiler/nova/frontend/lexer.nova"
    ,
        "compiler/nova/macros/macro_splice.nova",
        "compiler/nova/macros/macro_expand.nova",
        "compiler/nova/macros/constant_eval.nova"};
    char*sources[18]={0};NtFInput inputs[18];int all=1;
    for(unsigned i=0;i<18;i++){size_t n=0;sources[i]=loadf(paths[i],&n);inputs[i]=(NtFInput){paths[i],sources[i],n};if(!sources[i])all=0;}
    CHECK(all,"sources load");NtArtifact compiler={0};int compiled=all&&nova_compile_many_v2(inputs,18,&compiler);
    CHECK(compiled,"Nova modules compile");if(!compiled)fprintf(stderr,"E%u %zu:%zu %s\n",compiler.error.code,compiler.error.line,compiler.error.column,compiler.error.message);
    NovaHostImage image={0};CHECK(compiled&&nova_host_map(&compiler,&image),"host map");
    if(image.memory){
        /* ---- the two retained fixtures: identical declarations, section order
         *      and function order differ, the layout must not ---- */
        {
            static const Item classic[]={{"zeta",2,4660,2,1},{"alpha",1,42,2,0},
                                         {"beta",4,2018915346u,3,1}};
            simple_case(&image,"rdata_then_data",classic,3,0);
            simple_case(&image,"text_first",classic,3,1);
            /* the canonical payload of this fixture, spelled out so a reader can
             * check it by hand: alpha at 0, one zero pad, zeta at 2, four bytes.
             * The C oracle in layout_verdict is what proves it, not this text. */
            classic_payload(&image,classic);
        }
        /* ---- one item per width ---- */
        {
            static const Item singles[]={{"only",1,42,2,1},{"only",2,4660,2,1},
                                         {"only",4,2018915346u,2,1},{"only",8,0x1122334455667788ull,2,1}};
            for(unsigned w=0;w<4;w++){
                char label[32];snprintf(label,sizeof label,"single_u%u",singles[w].width*8);
                simple_case(&image,label,&singles[w],1,0);
            }
        }
        /* ---- the mixed width pairs, forwards and name reversed ---- */
        {
            static const Item pairs[]={
                {"aa",1,0x11,2,1},{"bb",8,0x2233445566778899ull,2,1},
                {"aa",8,0x2233445566778899ull,2,1},{"bb",1,0x11,2,1},
                {"aa",2,0x1122,2,1},{"bb",4,0x33445566u,2,1},
                {"aa",4,0x33445566u,2,1},{"bb",2,0x1122,2,1},
                {"zz",1,0x11,2,1},{"aa",8,0x2233445566778899ull,2,1},
                {"zz",8,0x2233445566778899ull,2,1},{"aa",1,0x11,2,1},
                {"bb",2,0x1122,2,1},{"aa",4,0x33445566u,2,1},
                {"bb",4,0x33445566u,2,1},{"aa",2,0x1122,2,1}};
            static const char *pair_labels[]={
                "u8_then_u64","u64_then_u8","u16_then_u32","u32_then_u16",
                "reversed_u8_u64","reversed_u64_u8","reversed_u16_u32","reversed_u32_u16"};
            for(unsigned i=0;i<8;i++)simple_case(&image,pair_labels[i],&pairs[i*2],2,0);
        }
        /* ---- all four widths in one section, three declaration orders ---- */
        {
            static const Item up[]={{"a",1,1,2,1},{"b",2,2,2,1},{"c",4,3,2,1},{"d",8,4,2,1}};
            static const Item down[]={{"d",8,4,2,1},{"c",4,3,2,1},{"b",2,2,2,1},{"a",1,1,2,1}};
            static const Item swapped[]={{"d",8,4,2,1},{"b",2,2,2,1},{"c",4,3,2,1},{"a",1,1,2,1}};
            simple_case(&image,"four_widths_ascending",up,4,0);
            simple_case(&image,"four_widths_descending",down,4,0);
            simple_case(&image,"four_widths_mid_swap",swapped,4,0);
        }
        /* ---- every alignment boundary a wider item can land on ---- */
        {
            static const Item pad1[]={{"a",1,1,2,1},{"z",2,2,2,1}};
            static const Item pad2[]={{"a",1,1,2,1},{"b",1,2,2,1},{"z",4,3,2,1}};
            static const Item pad3[]={{"a",1,1,2,1},{"b",1,2,2,1},{"c",1,3,2,1},{"z",8,4,2,1}};
            static const Item pad4[]={{"a",1,1,2,1},{"b",1,2,2,1},{"c",1,3,2,1},{"d",1,4,2,1},{"z",8,5,2,1}};
            static const Item pad5[]={{"a",1,1,2,1},{"b",1,2,2,1},{"c",1,3,2,1},{"d",1,4,2,1},
                                      {"e",1,5,2,1},{"z",8,6,2,1}};
            static const Item pad7[]={{"a",1,1,2,1},{"b",1,2,2,1},{"c",1,3,2,1},{"d",1,4,2,1},
                                      {"e",1,5,2,1},{"f",1,6,2,1},{"g",1,7,2,1},{"z",8,8,2,1}};
            static const Item pad8[]={{"a",1,1,2,1},{"b",1,2,2,1},{"c",1,3,2,1},{"d",1,4,2,1},
                                      {"e",1,5,2,1},{"f",1,6,2,1},{"g",1,7,2,1},{"h",1,8,2,1},{"z",8,9,2,1}};
            static const Item u16x3[]={{"a",2,1,2,1},{"b",2,2,2,1},{"c",2,3,2,1},{"z",8,4,2,1}};
            static const Item u16x5[]={{"a",2,1,2,1},{"b",2,2,2,1},{"c",2,3,2,1},{"d",2,4,2,1},
                                       {"e",2,5,2,1},{"z",8,6,2,1}};
            static const Item u32x1[]={{"a",4,1,2,1},{"z",8,2,2,1}};
            static const Item u32x3[]={{"a",4,1,2,1},{"b",4,2,2,1},{"c",4,3,2,1},{"z",8,4,2,1}};
            static const Item u32u8[]={{"a",4,1,2,1},{"b",1,2,2,1},{"c",1,3,2,1},{"d",1,4,2,1},{"z",8,5,2,1}};
            static const Item u16u8[]={{"a",2,1,2,1},{"b",1,2,2,1},{"z",8,3,2,1}};
            simple_case(&image,"align2_after_1_u8",pad1,2,0);
            simple_case(&image,"align4_after_2_u8",pad2,3,0);
            simple_case(&image,"align8_after_3_u8",pad3,4,0);
            simple_case(&image,"align8_after_4_u8",pad4,5,0);
            simple_case(&image,"align8_after_5_u8",pad5,6,0);
            simple_case(&image,"align8_after_7_u8",pad7,8,0);
            simple_case(&image,"align8_at_8_u8",pad8,9,0);
            simple_case(&image,"align8_after_3_u16",u16x3,4,0);
            simple_case(&image,"align8_after_5_u16",u16x5,6,0);
            simple_case(&image,"align8_after_1_u32",u32x1,2,0);
            simple_case(&image,"align8_after_3_u32",u32x3,4,0);
            simple_case(&image,"align8_after_u32_3_u8",u32u8,5,0);
            simple_case(&image,"align8_after_u16_u8",u16u8,3,0);
        }
        /* ---- byte order, not locale or declaration order ---- */
        {
            static const Item ascii[]={{"Z",1,1,2,1},{"_x",4,2,2,1},{"abc",2,3,2,1},{"a",8,4,2,1}};
            static const Item digits[]={{"e0",1,1,2,1},{"d0",8,2,2,1},{"d00",2,3,2,1},{"a0",4,4,2,1}};
            static const Item prefix[]={{"ab",8,1,2,1},{"a",1,2,2,1},{"abc",2,3,2,1},{"b",4,4,2,1}};
            static const Item mixedcase[]={{"aB",1,1,2,1},{"Ab",2,2,2,1},{"AB",4,3,2,1},{"a",8,4,2,1}};
            simple_case(&image,"byte_order_mixed",ascii,4,0);
            simple_case(&image,"byte_order_digits",digits,4,0);
            simple_case(&image,"byte_order_prefix",prefix,4,0);
            simple_case(&image,"byte_order_case",mixedcase,4,0);
        }
        /* ---- both sections at once, and the export flag must not move a byte ---- */
        {
            static const Item two[]={{"zeta",2,4660,2,1},{"alpha",1,42,2,1},{"beta",4,2018915346u,3,1}};
            static const Item flags[]={{"zeta",2,4660,2,1},{"alpha",1,42,2,0},{"beta",4,2018915346u,3,0}};
            static const Item split[]={{"zeta",8,4660,2,1},{"alpha",1,42,3,1},{"beta",2,7,3,1}};
            static const Item interleave[]={{"m1",1,1,2,1},{"m2",8,2,3,1},{"m3",2,3,2,1},{"m4",4,4,3,1}};
            simple_case(&image,"two_sections_classic",two,3,0);
            simple_case(&image,"two_sections_split",split,3,0);
            simple_case(&image,"two_sections_interleaved",interleave,4,0);
            simple_case(&image,"exported_flags",flags,3,0);
        }
        /* ---- the 1..64 item sweep, mixed widths, ascending names ---- */
        {
            Item sweep[MAX_ITEMS];
            char names[MAX_ITEMS][8];
            size_t i;
            for(i=0;i<MAX_ITEMS;i++){
                static const unsigned widths[4]={1,2,4,8};
                snprintf(names[i],sizeof names[i],"d%02zu",i);
                sweep[i]=(Item){names[i],widths[i%4],(uint64_t)(i*3+1),2,i%2==0};
            }
            for(i=1;i<=MAX_ITEMS;i++){
                char label[32],source[SRCROOM],twin[SRCROOM];
                snprintf(label,sizeof label,"sweep_%zu",i);
                if(build_source(source,sizeof source,sweep,i,BODY_N_MAIN_FIRST,0)>sizeof source||
                   build_source(twin,sizeof twin,sweep,i,BODY_C,0)>sizeof twin){
                    CHECKL(0,"sweep fixture fits",label);break;
                }
                pe_case(&image,label,source,twin,0);
            }
        }
        /* ---- the declaration index tiebreak of the name order is unreachable:
         *      both producers refuse two data items of the same name. Asserted. */
        {
            const char *twin_dup="module m\ntarget x86_64-nexora-uefi\nsection .rdata {\n"
                "export data aa:u8=1\nexport data aa:u8=2\n}\n"
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
        const char*bad_range="module m\ntarget x86_64-nexora-uefi\nsection .rdata {\nexport data alpha:u8=256\n}\nsection .text {\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nret\n}\nfn helper()->u64\neffects {}\nclobbers {} {\nret\n}\n}\n";
        const char*bad_duplicate="module m\ntarget x86_64-nexora-uefi\nsection .rdata {\nexport data helper:u8=1\n}\nsection .text {\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nret\n}\nfn helper()->u64\neffects {}\nclobbers {} {\nret\n}\n}\n";
        const char*bad_duplicate_data="module m\ntarget x86_64-nexora-uefi\nsection .rdata {\nexport data alpha:u8=1\n}\nsection .data {\nexport data alpha:u8=2\n}\nsection .text {\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nret\n}\nfn helper()->u64\neffects {}\nclobbers {} {\nret\n}\n}\n";
        const char*bad_main_collision="module m\ntarget x86_64-nexora-uefi\nsection .rdata {\nexport data main:u8=1\n}\nsection .text {\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nret\n}\nfn helper()->u64\neffects {}\nclobbers {} {\nret\n}\n}\n";
        const char*bad_section="module m\ntarget x86_64-nexora-uefi\nsection .bss {\nexport data alpha:u8=1\n}\nsection .text {\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nret\n}\nfn helper()->u64\neffects {}\nclobbers {} {\nret\n}\n}\n";
        rejected(&image,bad_range,65536,800,"out-of-range scalar transactional");
        rejected(&image,bad_duplicate,65536,800,"duplicate symbol transactional");
        rejected(&image,bad_duplicate_data,65536,800,"duplicate data names transactional");
        rejected(&image,bad_main_collision,65536,800,"main/data name collision transactional");
        rejected(&image,bad_section,65536,800,"unsupported section transactional");
        }
        {
            char source[SRCROOM],twin[SRCROOM];
            static const Item classic[]={{"zeta",2,4660,2,1},{"alpha",1,42,2,0},
                                         {"beta",4,2018915346u,3,1}};
            if(build_source(source,sizeof source,classic,3,BODY_N_MAIN_FIRST,0)>sizeof source||
               build_source(twin,sizeof twin,classic,3,BODY_C,0)>sizeof twin)
                CHECK(0,"short PE fixture bounded");
            else rejected(&image,source,16,827,"short PE output transactional");
        }
        {
            char*many=malloc(4096);
            CHECK(many!=NULL,"65-data fixture allocation");
            if(many){
                size_t at=(size_t)sprintf(many,"module m\ntarget x86_64-nexora-uefi\nsection .rdata {\n");
                for(unsigned i=0;i<65;i++)at+=(size_t)sprintf(many+at,"export data item%02u:u8=%u\n",i,i);
                at+=(size_t)sprintf(many+at,"}\nsection .text {\nfn main()->u64\neffects {}\nclobbers {} {\ncall helper()\nret\n}\nfn helper()->u64\neffects {}\nclobbers {} {\nret\n}\n}\n");
                CHECK(at<4096,"65-data fixture bounded");
                rejected(&image,many,65536,800,"more than 64 data transactional");
                free(many);
            }
        }
    }
    if(image.memory)nova_host_unmap(&image);
    if(compiled)nt_artifact_free(&compiler);
    for(unsigned i=0;i<18;i++)free(sources[i]);

    /* ---- the contract oracle: the varied contract text of the C object
     *      writer, through the C reader and through the Nova accessor ---- */
    {
        NovaHostImage accessor = {0};
        NtArtifact accessor_artifact = {0};
        if (contract_image(&accessor, &accessor_artifact)) contract_suite(&accessor);
        if (accessor.memory) nova_host_unmap(&accessor);
        nt_artifact_free(&accessor_artifact);
    }
printf("NTASM_NOVA_X64_LOWER_NXO_LOCAL_DATA_PE checks=%u failures=%u cases=%u\n",checks,failures,cases);
    return failures?1:0;
}
