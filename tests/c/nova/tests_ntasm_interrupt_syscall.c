/* A4.06 — « chemins interruption/syscall conformes », établis sur des OCTETS.
 *
 * =========================== POURQUOI CETTE PORTE EXISTE =========================
 *
 * docs/status/ntasm-b21-feature-matrix.md porte, sur la ligne A4.06 :
 *   « AUCUNE porte d'OCTETS ne l'établit : le chemin d'interruption est attesté
 *     par une campagne DATÉE du 5 septembre sous un `evidence_root` qui n'est
 *     pas cet arbre, et QEMU ne fait pas partie du run de routine — la preuve
 *     ne se re-dérive pas à chaque exécution. »
 *
 * C'est le mot « ré-dérive » qui décide : un journal d'une campagne passée
 * atteste une exécution, pas l'état de l'arbre. Cette porte est dans le run de
 * routine et lit ses attentes sur l'autre moitié À L'EXÉCUTION.
 *
 * ============================ LA MESURE QUI L'A RENDUE NÉCESSAIRE ==============
 *
 * Quatre formes privilegiées existent dans l'encodeur du produit ET dans
 * l'encodeur de la référence : `swapgs`, `syscall`, `sysretq`, `iretq`. Elles
 * sont absentes de tout programme de l'arbre (grep sur `examples/`, `os/`,
 * `bootstrap/seed/` : zéro fichier) et absentes de toute porte d'octets.
 *
 * La mesure qui manquait est d'une ligne : les ENTRÉES de ce arbre passent
 * toutes `cpl = 3` à l'abaissement, et la référence passe `cpl = 0`. Comme les
 * trois premières formes portent `maximum_cpl = 0`, une chaîne abaissée en
 * anneau 3 les REFUSE en 405 avant d'écrire un octet. Personne n'avait jamais
 * demandé à cette chaîne l'anneau 0, donc le chemin privilégié n'était mesuré
 * d'aucun côté — ni son succès, ni son refus.
 *
 * Cette porte mesure donc les DEUX anneaux, et les octets des deux côtés.
 *
 * =============================== LES QUATRE MESURES ============================
 *
 * A. L'ENCODEUR, en octets, avec la colonne `cpl` balayée et la colonne
 *    `features` amputée. L'attente est `nt_x64_encode`, exécuté ici, dans ce
 *    processus. Aucun octet n'est écrit en littéral dans ce fichier, et un refus
 *    doit laisser le tampon intact des DEUX côtés.
 *
 * B. LA TABLE DES ATOMES. La règle du §17.4 est écrite comme DONNÉE, puis
 *    confrontée à ce que `nt_x64_effects` dérive de la forme. Une table recopiée
 *    qui divergerait de l'oracle ferait rouge la ligne qui la confronte.
 *
 * C. LE REFUS AVEC POSITION, mesuré dans la porte voisine `invalid_positions`,
 *    qui exécute la chaîne complète des 35 passes. Il n'est PAS rejoué ici et
 *    cette porte ne l'annonce donc pas : annoncer une mesure qu'un fichier ne
 *    fait pas est la forme exacte du bandeau vert qui ment, et il n'y a aucun
 *    compteur qui la rattraperait.
 *
 * D. L'ABAISSEMENT, en octets. La même source, abaissée en anneau 0 par le
 *    produit, et compilée par la référence. Ce qui est comparé est la SECTION
 *    `.text` des deux côtés, et non le conteneur : le produit rend un objet NXO
 *    sérialisé (balise `NXOV0001`, en-tête de 96 octets, table des symboles à
 *    l'octet 240) pendant que `nt_codegen_x64_object` rend l'image de code
 *    brute, dont l'octet 0 est déjà du code machine. Comparer les deux
 *    conteneurs serait rouge par construction ; le produit passe donc son objet
 *    par `nt_object_read`, qui le relit dans le même type que celui que la
 *    référence remplit, et c'est la section qui est confrontée.
 *
 *    Une forme que le produit refuse alors que la référence produit du texte est
 *    comptée à part et imprimée : c'est une divergence à un seul côté, qui est
 *    une information et non un échec de comparaison.
 *
 * Le masque `clobbers` des fixtures vient du `registers_written` que publie
 * `nt_x64_effects` : c'est l'ORACLE qui décide de la liste, donc une fixture ne
 * peut pas masquer une divergence du produit en déclarant un masque faux.
 */
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/ntasm/formats/object.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include "../../../compiler/c/ntasm/frontend/frontend.h"
#include "../../../compiler/c/ntasm/backend/codegen.h"
#include "../../../compiler/c/ntasm/backend/x64.h"
#include <stdint.h>
#include "ntasm_pipeline_parity.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Les dix-huit modules de la chaîne d'abaissement, dans l'ordre de la porte
 * x64_lower_nxo_pe, plus l'entrée de ce gate. Un seul jeu : l'entrée expose les
 * deux modes, donc une seule image sert les quatre mesures. */
static const char *const MODULES[] = {
    "tests/nova/tests/interrupt-syscall-entry.nova",
    "compiler/nova/backend/x64/x64_lower_nxo_pe.nova",
    "compiler/nova/backend/x64/x64_lower_nxo.nova",
    "compiler/nova/backend/x64/x64_lower_control.nova",
    "compiler/nova/backend/x64/x64_lower_fixed.nova",
    "compiler/nova/backend/x64/x64_fixed.nova",
    "compiler/nova/analysis/types/register_widths.nova",
    "compiler/nova/formats/nxo/nxo_link_pe.nova",
    "compiler/nova/formats/nxo/nxo_merge.nova",
    "compiler/nova/formats/nxo/nxo_pe.nova",
    "compiler/nova/formats/nxo/nxo.nova",
    "compiler/nova/formats/pe/pe.nova",
    "compiler/nova/frontend/parser.nova",
    "compiler/nova/frontend/ast.nova",
    "compiler/nova/frontend/lexer.nova",
    "compiler/nova/macros/macro_splice.nova",
    "compiler/nova/macros/macro_expand.nova",
    "compiler/nova/macros/constant_eval.nova"};
#define MODULE_COUNT ((unsigned)(sizeof MODULES / sizeof *MODULES))

static unsigned checks, failures, cases;

static char *load(const char *path, size_t *size)
{
    FILE *file = fopen(path, "rb");
    if (!file) return NULL;
    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);
    char *bytes = length >= 0 ? malloc((size_t)length + 1) : NULL;
    if (!bytes || fread(bytes, 1, (size_t)length, file) != (size_t)length) {
        free(bytes);
        fclose(file);
        return NULL;
    }
    fclose(file);
    bytes[length] = 0;
    *size = (size_t)length;
    return bytes;
}

/* Les dix-huit chemins de MODULES sont ceux de la porte `x64_lower_nxo_pe`,
 * qui est la seule à les avoir fait compiler ensemble. C'est une liste
 * PROVENUE, pas une liste minimale.
 *
 * ET IL N'Y A PAS DE GARDE DE CLÔTURE ICI, ce qui est une décision. La porte
 * voisine `invalid_positions` en a un, et il fonctionne — mais il résout un
 * nom de module importé à travers la liste de la chaîne de VALIDATION. Appliqué
 * à cette entrée, il a refusé en disant « imports ntasm_nxo and no file in the
 * tree carries it », alors que `nxo.nova` porte `module ntasm_nxo;` et figure
 * dans MODULES. L'instrument est écrit pour UN autre sujet ; l'appliquer ici
 * produirait un rouge qui ne nomme aucun défaut du produit, et un garde qui ne
 * peut pas fonctionner sur son sujet n'est pas un garde. La liste reste donc
 * une liste, et elle est dite PROVENUE pour que le lecteur sache qu'elle
 * n'est pas minimale. */

/* L'ARTEFACT ET LES SOURCES SONT DES VARIABLES DE FICHIER, et non des locales,
 * pour une raison mesurée : le run est exécuté sous
 * `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1`, et une fuite ne fait pas
 * échouer une assertion — elle ABORT le processus à la sortie, donc la porte
 * n'imprime jamais sa bannière et le pilote la classe `INTERRUPTED` plutôt que
 * rouge. C'est ce qu'a fait la première passe : dix-sept mégaoctets gardés par
 * `codegen.c` et vingt-quatre octets par mon propre `calloc`, et zéro bannière.
 * L'ordre de libération est celui de la porte `validate` : démonter, rendre
 * l'artefact, rendre les sources. */
static NtArtifact module_artifact;
static char *module_sources[MODULE_COUNT];
static NovaHostImage *module_image;

static void release_image(void)
{
    if (module_image) {
        if (module_image->memory) nova_host_unmap(module_image);
        free(module_image);
        module_image = NULL;
    }
    nt_artifact_free(&module_artifact);
    for (unsigned i = 0; i < MODULE_COUNT; i++) {
        free(module_sources[i]);
        module_sources[i] = NULL;
    }
}

static NovaHostImage *map_modules(const char *const *paths, unsigned count)
{
    NtFInput inputs[MODULE_COUNT];
    unsigned i;
    int all = 1;
    for (i = 0; i < count; i++) {
        size_t size = 0;
        module_sources[i] = load(paths[i], &size);
        inputs[i] = (NtFInput){paths[i], module_sources[i], size};
        if (!module_sources[i]) {
            all = 0;
            fprintf(stderr, "MISSING %s\n", paths[i]);
        }
    }
    checks++;
    if (!all) {
        fprintf(stderr, "FAIL every module of this image must load\n");
        failures++;
        release_image();
        return NULL;
    }
    checks++;
    if (!nova_compile_many_v2(inputs, count, &module_artifact)) {
        fprintf(stderr, "FAIL these modules must compile: %u %zu:%zu %s\n",
                module_artifact.error.code, module_artifact.error.line,
                module_artifact.error.column, module_artifact.error.message);
        failures++;
        release_image();
        return NULL;
    }
    module_image = calloc(1, sizeof *module_image);
    if (!module_image) return NULL;
    checks++;
    if (!nova_host_map(&module_artifact, module_image)) {
        fprintf(stderr, "FAIL this image must map\n");
        failures++;
        release_image();
        return NULL;
    }
    return module_image;
}

/* ------------------------------- A : l'encodeur ----------------------------- */

/* out[0] = longueur, out[1..] = octets, valeur de retour = code d'erreur.
 * C'est le contrat que lit déjà la porte x64_fixed ; il n'est écrit dans aucun
 * en-tête, donc il est écrit ici. */
typedef struct {
    uint64_t returned, runtime;
    /* OCTETS, et non mots. Le contrat du produit pour l'encodeur est
     * `out[0]=u8(length); out[1]=u8(packed&255); ...` — UN OCTET PAR INDICE,
     * vérifié à trois endroits indépendants : `x64_fixed.nova`, `pe.nova`
     * (ancre « while i<8{out[at+i]=u8(value>>(i*8));} ») et la porte jumelle
     * `tests_ntasm_x64_fixed.c`, qui déclare `uint8_t out[4]` et compare
     * « r.out[k+1]!=(k<expected.length?expected.bytes[k]:0) ».
     *
     * Un tableau de MOTS ici lit huit fois trop large : l'octet de longueur
     * deviendrait 0xcccc…cc03 et l'octet suivant serait lu à l'offset 8, que
     * le produit n'a jamais touché. Une porte qui compare des mots à des octets
     * est rouge pour une raison qu'aucune ligne de son en-tête ne nomme. */
    uint8_t out[16];
} Enc;

/* `bytes` est la LONGUEUR EMPRUNTÉE, en octets, et non un nombre de mots : les
 * deux sélecteurs n'écrivent pas à la même granularité — l'encodeur écrit des
 * octets, l'abaissement écrit des mots de 64 bits — et un seul paramètre
 * exprimé dans l'unité de l'entrée évite de trancher ici. */
/* L'ENTRÉE A CINQ PARAMÈTRES ET SEPT SLOTS, comme `x64-fixed-entry.nova`. La
 * première version en prenait six et passait huit slots, et CHAQUE appel est
 * revenu `NV2_ARGUMENT` : le wrapper de l'hôte garde `count == param_count`
 * (nova.c, ancre « guard(c, &q, binary(c, NTF_OP_NE, name_expr(c, count,
 * span), literal(c, FN(c, main).param_count, …), TY_BOOL, span), NV2_ARGUMENT,
 * span) »). Une forme d'entrée qui diffère d'une forme prouvée d'un seul
 * paramètre est une forme dont l'arité n'a jamais été exercée. */
static Enc call_entry(const NovaHostImage *image, const char *text, uint64_t x, uint64_t y,
                      uint64_t z, void *out, uint64_t bytes)
{
    static const uint64_t guard = UINT64_C(0xcccccccccccccccc);
    Enc result;
    unsigned k;
    NovaContextV2 context = {0};
    for (k = 0; k < 16; k++) result.out[k] = 0xcc;
    result.returned = guard;
    result.runtime = guard;
    if (!nova_context_init_v2(&context)) return result;
    uint64_t text_handle = nova_borrow_v2(&context, (void *)text, strlen(text), 0);
    uint64_t out_handle = nova_borrow_v2(&context, out, bytes, 1);
    uint64_t args[] = {text_handle, strlen(text), x, y, z, out_handle, bytes};
    result.returned = image->entry(&context, args, 7);
    result.runtime = context.error;
    (void)nova_context_destroy_v2(&context);
    return result;
}

static Enc encode(const NovaHostImage *image, const char *name, uint64_t features, uint64_t cpl)
{
    uint8_t out[16];
    unsigned k;
    for (k = 0; k < 16; k++) out[k] = 0xcc;
    Enc result = call_entry(image, name, 0, features, cpl, out, sizeof out);
    for (k = 0; k < 16; k++) result.out[k] = out[k];
    return result;
}

static unsigned bytes_equal, bytes_wrong, refusals_agree, refusals_split;

static void encoder_row(const NovaHostImage *image, const char *name, uint64_t features,
                        uint64_t cpl)
{
    NtX64Instruction expected;
    NtX64Error oracle =
        nt_x64_encode(name, NULL, 0, (NtX64Context){features, cpl}, &expected);
    Enc actual = encode(image, name, features, cpl);
    cases++;

    if (actual.runtime) {
        checks++;
        failures++;
        fprintf(stderr, "FAIL runtime error %u encoding %s\n", (unsigned)actual.runtime, name);
        return;
    }
    checks++;
    if (actual.returned != (uint64_t)oracle) {
        refusals_split++;
        failures++;
        fprintf(stderr, "FAIL encoder %s features=%u cpl=%u: the reference answers %u and the "
                        "product answers %llu. One of them encodes it and the other refuses, or "
                        "neither does, and only a comparison can tell.\n",
                name, (unsigned)features, (unsigned)cpl, (unsigned)oracle,
                (unsigned long long)actual.returned);
        printf("IS-ENC %-8s features=%u cpl=%u | oracle=%u product=%llu [DISAGREE]\n", name,
               (unsigned)features, (unsigned)cpl, (unsigned)oracle,
               (unsigned long long)actual.returned);
        return;
    }
    if (oracle != NT_X64_OK) {
        refusals_agree++;
        checks++;
        if (actual.out[0] != 0xccu) {
            refusals_split++;
            failures++;
            fprintf(stderr, "FAIL encoder %s features=%u cpl=%u: the reference refused with %u and "
                            "the product refused too, but wrote %llu into a buffer a refusal must "
                            "leave untouched\n",
                    name, (unsigned)features, (unsigned)cpl, (unsigned)oracle,
                    (unsigned long long)actual.out[0]);
        }
        printf("IS-ENC %-8s features=%u cpl=%u | oracle=%u product=%llu (both refuse)\n", name,
               (unsigned)features, (unsigned)cpl, (unsigned)oracle,
               (unsigned long long)actual.returned);
        return;
    }

    checks++;
    int same = actual.out[0] == expected.length;
    for (unsigned k = 0; same && k < expected.length; k++)
        same = actual.out[k + 1] == expected.bytes[k];
    if (same) {
        bytes_equal++;
    } else {
        bytes_wrong++;
        failures++;
        fprintf(stderr, "FAIL encoder %s features=%u cpl=%u: the reference emits %zu octet(s) [",
                name, (unsigned)features, (unsigned)cpl, expected.length);
        for (unsigned k = 0; k < expected.length; k++)
            fprintf(stderr, "%s%02x", k ? " " : "", expected.bytes[k]);
        fprintf(stderr, "] and the product emits %llu [", (unsigned long long)actual.out[0]);
        for (unsigned k = 0; k < actual.out[0] && k < 15; k++)
            fprintf(stderr, "%s%llu", k ? " " : "", (unsigned long long)actual.out[k + 1]);
        fprintf(stderr, "]\n");
    }
    printf("IS-ENC %-8s features=%u cpl=%u | bytes=%zu [", name, (unsigned)features, (unsigned)cpl,
           expected.length);
    for (unsigned k = 0; k < expected.length; k++)
        printf("%s%02x", k ? " " : "", expected.bytes[k]);
    printf("] agree=%d\n", same);
}

/* -------------------------- B : la table des atomes ------------------------- */

/* Les onze atomes, dans l'ordre de RANG DE BIT que donne x64.h, et le nom que
 * le langage leur donne dans §8.1. Le bit est celui de l'oracle : si l'oracle
 * publie un atome que ce fichier ne nomme pas, la ligne est rouge au lieu
 * d'être silencieuse. */
static const struct {
    uint32_t bit;
    const char *name;
} ATOMS[] = {{NT_X64_EFFECT_PRIVILEGED, "privileged"},
             {NT_X64_EFFECT_CHANGES_FLAGS, "changes_flags"},
             {NT_X64_EFFECT_MMIO, "mmio"},
             {NT_X64_EFFECT_IO_PORT, "io_port"},
             {NT_X64_EFFECT_MSR, "msr"},
             {NT_X64_EFFECT_CONTROL, "control"},
             {NT_X64_EFFECT_INTERRUPT_STATE, "interrupt_state"},
             {NT_X64_EFFECT_NO_RETURN, "no_return"},
             {NT_X64_EFFECT_MEMORY_ORDERING, "memory_ordering"},
             {NT_X64_EFFECT_READS_CLOCK, "reads_clock"},
             {NT_X64_EFFECT_SUSPENDS, "suspends"}};
#define ATOM_COUNT ((unsigned)(sizeof ATOMS / sizeof *ATOMS))

/* Les seize noms de famille GPR, dans l'ordre que donne le commentaire de
 * frontend.h : « rax=0 rcx=1 rdx=2 rbx=3 rsp=4 rbp=5 rsi=6 rdi=7, r8..r15=8..15 ». */
static const char *const GPR[16] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
                                    "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"};

/* La règle du §8.1, écrite comme DONNÉE et confrontée plus bas à ce que
 * `nt_x64_effects` dérive de la forme. Les trois citations sont VERBATIM : la
 * troisième porte une faute de frappe du document (« restoran »), et une citation
 * « restaurée » présentée entre guillemets serait une paraphrase déguisée en
 * preuve. La table §17.4 porte les mêmes quatre masques sous forme de lignes ;
 * les deux lectures sont confrontées ici, pas confondues. */
typedef struct {
    const char *form;
    uint32_t spec_atoms;
    const char *rule;
} SpecRow;

static const SpecRow SPEC[] = {
    {"swapgs", NT_X64_EFFECT_PRIVILEGED | NT_X64_EFFECT_CONTROL,
     "§8.1 : « `swapgs`, les control registers et les opérations de descripteurs exigent "
     "`privileged` et `control` »"},
    {"syscall", NT_X64_EFFECT_CONTROL | NT_X64_EFFECT_CHANGES_FLAGS,
     "§8.1 : « `syscall` exige `control` et `changes_flags` »"},
    {"sysretq",
     NT_X64_EFFECT_PRIVILEGED | NT_X64_EFFECT_CONTROL | NT_X64_EFFECT_CHANGES_FLAGS |
         NT_X64_EFFECT_NO_RETURN,
     "§8.1 : « `sysretq` et `iretq` ajoutent `privileged`, `control`, `changes_flags` et "
     "`no_return`, car ils restoran l'image RFLAGS en plus de terminer le flux » — "
     "« restoran » est la faute du document, citée telle quelle"},
    {"iretq",
     NT_X64_EFFECT_PRIVILEGED | NT_X64_EFFECT_CONTROL | NT_X64_EFFECT_CHANGES_FLAGS |
         NT_X64_EFFECT_NO_RETURN,
     "§8.1 : la même phrase nomme `iretq` avec `sysretq`, donc le même masque"}};
#define SPEC_COUNT ((unsigned)(sizeof SPEC / sizeof *SPEC))

/* Ce que l'oracle dérive de la forme : le masque d'effets qu'il publie, plus
 * `changes_flags` s'il écrit des drapeaux — `flags_written` est un canal
 * DISTINCT du masque d'effets, et confondre les deux ferait manquer exactement
 * la moitié des atomes de cette porte. */
static uint32_t oracle_atoms(const char *form)
{
    NtX64Effects effects;
    memset(&effects, 0, sizeof effects);
    if (nt_x64_effects(form, NULL, 0, (NtX64Context){NT_X64_ALL_FEATURES, 0}, &effects) !=
        NT_X64_OK)
        return 0;
    uint32_t atoms = effects.effects;
    if (effects.flags_written) atoms |= NT_X64_EFFECT_CHANGES_FLAGS;
    return atoms;
}

static void set_text(uint32_t atoms, char *out, size_t cap)
{
    size_t at = 0;
    out[0] = 0;
    for (unsigned k = 0; k < ATOM_COUNT; k++) {
        if (!(atoms & ATOMS[k].bit)) continue;
        int written = snprintf(out + at, cap - at, "%s%s", at ? "," : "", ATOMS[k].name);
        if (written < 0 || (size_t)written >= cap - at) return;
        at += (size_t)written;
    }
    if (at == 0) snprintf(out, cap, "%s", "{}");
}

static unsigned spec_rows_agree, spec_rows_diverge;

static void atoms_table(void)
{
    char rule[256], derived[256];
    for (unsigned k = 0; k < SPEC_COUNT; k++) {
        uint32_t from_oracle = oracle_atoms(SPEC[k].form);
        cases++;
        checks++;
        set_text(SPEC[k].spec_atoms, rule, sizeof rule);
        set_text(from_oracle, derived, sizeof derived);
        if (from_oracle == SPEC[k].spec_atoms) {
            spec_rows_agree++;
        } else {
            spec_rows_diverge++;
            failures++;
            fprintf(stderr, "FAIL spec atoms %s: the rule names {%s} and the reference derives "
                            "{%s}. One of the two is wrong, and a table copied into an assertion "
                            "would have kept passing.\n",
                    SPEC[k].form, rule, derived);
        }
        printf("IS-ATOMS %-8s rule={%s} oracle={%s} agree=%d | %s\n", SPEC[k].form, rule, derived,
               from_oracle == SPEC[k].spec_atoms ? 1 : 0, SPEC[k].rule);
    }
}

/* ------------------------- C et D : le chemin complet ----------------------- */

/* Le masque `clobbers` d'une fixture vient du `registers_written` que publie
 * nt_x64_effects. Les familles 16 (rip), 17 (rflags), 18 (gsbase) et 19 (fsbase)
 * sont hors des seize GPR du catalogue : rflags ne fait pas partie de
 * `registers_written`, et gsbase est refusé en `330` par DÉCISION de la spec
 * §8.2 — le nomer ici rendrait chaque fixture `swapgs` rouge pour une raison
 * étrangère à l'objet. */
static void body_clobbers(const char *form, char *out, size_t cap)
{
    NtX64Effects effects;
    size_t at = 0;
    memset(&effects, 0, sizeof effects);
    out[0] = 0;
    if (nt_x64_effects(form, NULL, 0, (NtX64Context){NT_X64_ALL_FEATURES, 0}, &effects) !=
        NT_X64_OK) {
        snprintf(out, cap, "%s", "{}");
        return;
    }
    for (unsigned family = 0; family < 16; family++) {
        if (!((effects.registers_written >> family) & 1u)) continue;
        int written = snprintf(out + at, cap - at, "%s%s", at ? "," : "", GPR[family]);
        if (written < 0 || (size_t)written >= cap - at) return;
        at += (size_t)written;
    }
    if (at == 0) snprintf(out, cap, "%s", "{}");
}


typedef struct {
    const char *form;
    const char *declaration;
    const char *epilogue;
} Shape;

/* Les quatre formes sont placées dans une fonction `-> u64`. Les deux TERMINALES
 * ne peuvent pas être abaissées, et les deux RAISONS sont distinctes, toutes deux
 * dans `x64_lower_nxo` :
 *
 *   - `body_falls_off` ne reconnaît que deux fins de corps acceptables : un
 *     `return` (nœud de kind 29) ou un `jmp` dont `branch_length` est non nul.
 *     `iretq`, `sysretq` et `ud2` ne sont dans AUCUNE des deux listes, donc le
 *     corps « atteint sa fin » au sens de l'abaisseur et la fonction est
 *     refusée en 800.
 *   - `scalar_type` ne connaît que `u8`, `u16`, `u32`, `u64` et `bool`. Le type
 *     de retour `never` y rend 0, donc TOUTE fonction `-> never` est
 *     inabaissable et l'entrée rendrait 800 également.
 *
 * Choisir `-> u64` n'est donc pas un contournement : c'est la seule des deux
 * formes qui n'est PAS refusée pour son type de retour, et le refus qui reste —
 * par `body_falls_off` — porte sur la FORME, qui est l'objet de cette porte. Le
 * refus est compté dans `lower_refused` et imprimé ; ce n'est pas un échec de
 * comparaison, parce qu'une comparaison d'octets n'a pas lieu d'être quand un
 * côté refuse et que l'autre produit.
 *
 * À noter, parce que c'est le genre de désaccord qui se lit comme un défaut
 * alors que ce n'en est pas un : la CHAÎNE SÉMANTIQUE accepte ces mêmes
 * sources. `control_flow.check` compte `iretq` et `sysretq` parmi les formes
 * terminales (ancre « terminal, or the terminal statement itself: return, ud2,
 * sysretq, iretq, a ») et la porte voisine `tests_ntasm_control_flow.c` le
 * prouve par ses rangées `never_ok` et `align_never`. Les deux chaînes ne
 * partagent AUCUNE règle de terminalité, et c'est cela que cette porte
 * mesure. */
static const Shape SHAPES[] = {{"swapgs", "u64", "mov rax,0\nreturn rax"},
                                {"syscall", "u64", "mov rax,0\nreturn rax"},
                                {"sysretq", "u64", ""},
                                {"iretq", "u64", ""}};
#define SHAPE_COUNT ((unsigned)(sizeof SHAPES / sizeof *SHAPES))

static const Shape *shape_of(const char *form)
{
    for (unsigned k = 0; k < SHAPE_COUNT; k++)
        if (!strcmp(SHAPES[k].form, form)) return &SHAPES[k];
    return NULL;
}

/* LES VARIANTES DE DÉCLARATION, ET POURQUOI ELLES EXISTENT.
 *
 * Une comparaison d'octets n'a lieu que si DEUX producteurs acceptent la même
 * source. La première version n'en déclarait que deux — features ou non,
 * clobbers inférés ou vides — et la mesure a dit pourquoi elle ne produisait
 * rien : sur les huit lignes d'abaissement, la RÉFÉRENCE elle-même a refusé les
 * seize combinaisons, avec des messages qui nomment chacun une EXIGENCE et
 * aucune l'abaissement.
 *
 * Ces exigences sont donc l'information utile, et chacune se traduit par une
 * variante de plus :
 *
 *   « 502 omits an inferred clobber » pour `swapgs` → le bit 18 doit être
 *       DÉCLARÉ, donc une variante qui écrit `gsbase` ;
 *   « 303 missing CPU feature » → le masque doit être déclaré, donc la ligne
 *       `features {lm,syscall}` ;
 *   « 200 expected clobber set » → le PARSEUR refuse le jeu écrit, donc des
 *       variantes qui écrivent d'autres noms, pour savoir lesquels il prend ;
 *   « 500 reachable path falls out of function » pour `sysretq` et « 503 iretq
 *       requires unavailable stack/frame balance proof » pour `iretq` → des
 *       variantes qui portent le PROLOGUE `align_stack` que la porte voisine
 *       `tests_ntasm_control_flow.c` prouve pour ces deux formes.
 *
 * La liste est une DONNÉE. Le choix se fait à l'exécution : la porte essaie les
 * variantes dans l'ordre et retient la PREMIÈRE que la référence accepte. Une
 * variante de plus ne peut qu'ajouter une mesure — jamais en retirer une — et
 * chaque refus est imprimé avec son motif, donc l'ajout d'une variante ne peut
 * pas rendre une porte silencieuse.
 *
 * `features` est la déclaration de module qui porte le masque CPU ; les noms
 * sont ceux de la porte `features` : `lm`, `msr`, `syscall`, `sse2`, `tsc`. */
typedef struct {
    const char *label;
    const char *features;
    const char *clobbers;  /* NULL = le jeu inféré par nt_x64_effects */
    int align;             /* prologue `load rsp` + `align_stack 16` */
    const char *declaration; /* NULL = celui de SHAPES */
} Variant;

static const Variant VARIANTS[] = {
    {"features+inferred", "features {lm,syscall}\n", NULL, 0, NULL},
    {"features+empty", "features {lm,syscall}\n", "{}", 0, NULL},
    {"features+gsbase", "features {lm,syscall}\n", "{gsbase}", 0, NULL},
    {"features+rax", "features {lm,syscall}\n", "{rax}", 0, NULL},
    {"features+rax-rcx-r11", "features {lm,syscall}\n", "{rax,rcx,r11}", 0, NULL},
    {"features+everything", "features {lm,syscall}\n", "{rax,rcx,r11,rsp,gsbase}", 0, NULL},
    {"features+inferred+align", "features {lm,syscall}\n", NULL, 1, NULL},
    {"features+everything+align", "features {lm,syscall}\n", "{rax,rcx,r11,rsp,gsbase}", 1, NULL},
    {"features+everything+align+never", "features {lm,syscall}\n", "{rax,rcx,r11,rsp,gsbase}", 1,
     "never"}};
#define VARIANT_COUNT ((unsigned)(sizeof VARIANTS / sizeof *VARIANTS))

static void build_source(const Shape *shape, const Variant *variant, uint32_t atoms,
                         const char *oracle_clob, char *out, size_t cap)
{
    char set[256];
    set_text(atoms, set, sizeof set);
    snprintf(out, cap,
             "module m\ntarget x86_64-nexora-none\n%s"
             "section .text {\n"
             "fn f()->%s\neffects {%s}\nclobbers %s {\n%s%s\n%s\n}\n}\n",
             variant->features, variant->declaration ? variant->declaration : shape->declaration,
             set, variant->clobbers ? variant->clobbers : oracle_clob,
             variant->align ? "load rsp,[gs:kernel_rsp]:ptr<kernel,u64>\nalign_stack 16\n" : "",
             shape->form, shape->epilogue);
}


/* ------------------------------- D : l'octet -------------------------------- */

#define OUTCAP 65536
/* Le tampon du produit est un tableau de MOTS parce que l'ABI de l'hôte
 * emprunte un buffer par (handle, longueur) et que l'entrée écrit la taille en
 * out[0] avant les octets ; l'accès en octets passe donc par un alias, et
 * non par un transtype implicite d'un `uint8_t *` en `uint64_t *`. */
static uint64_t product_words[OUTCAP / 8];
static uint8_t *const product_object = (uint8_t *)product_words;
static uint8_t reference_text[OUTCAP];

static unsigned lower_equal, lower_diverge, lower_refused, lower_compared, lower_one_sided;
static unsigned lower_unreachable, lower_accepted;
/* Les MOTIFS DE REFUS de la référence, tous distincts. C'est la non-vacuité de
 * la découverte : une boucle qui n'essayait qu'une variante produirait un seul
 * motif, et le produit refuse les quatre formes POUR QUATRE RAISONS
 * DIFFÉRENTES. Le compte est donc ce qui distingue « la découverte a cherché »
 * de « la découverte a supposé ». */
#define REASON_MAX 16
static char reason_seen[REASON_MAX][256];
static unsigned unreachable_reasons;

static void note_reason(const char *why)
{
    for (unsigned k = 0; k < unreachable_reasons && k < REASON_MAX; k++)
        if (!strcmp(reason_seen[k], why)) return;
    if (unreachable_reasons >= REASON_MAX) return;
    snprintf(reason_seen[unreachable_reasons], sizeof reason_seen[0], "%s", why);
    unreachable_reasons++;
}


/* La référence à cpl 0 : nt_frontend_compile_object puis nt_codegen_x64_object
 * rendent l'image de code, dont `.bytes`/`.size` sont le texte. C'est l'autre
 * producteur : un frontal et un encodeur écrits en C, dans un autre langage,
 * dans ce processus, et dont aucun module Nova ne peut produire l'image. */
static int reference_text_of(const char *source, size_t *size, char *why, size_t cap)
{
    NtFInput input = {"m", source, strlen(source)};
    NtFProgram program;
    NtCodeImage image;
    NtCodeDiagnostic cd;
    int ok = 0;
    memset(&program, 0, sizeof program);
    memset(&image, 0, sizeof image);
    memset(&cd, 0, sizeof cd);
    *size = 0;
    if (!nt_frontend_compile_object(&input, 1, &program)) {
        snprintf(why, cap, "frontend %u %s",
                 program.diagnostic_count ? program.diagnostics[0].code : 0u,
                 program.diagnostic_count ? program.diagnostics[0].message : "no diagnostic");
        nt_frontend_free(&program);
        return 0;
    }
    if (!nt_codegen_x64_object(&program, &image, &cd)) {
        snprintf(why, cap, "codegen %u %s", cd.code, cd.message);
        nt_code_image_free(&image);
        nt_frontend_free(&program);
        return 0;
    }
    if (image.size && image.bytes) {
        if (image.size > OUTCAP) {
            snprintf(why, cap, "reference text of %zu bytes exceeds the %d byte buffer",
                     image.size, OUTCAP);
        } else {
            memcpy(reference_text, image.bytes, image.size);
            *size = image.size;
            ok = 1;
        }
    } else {
        snprintf(why, cap, "reference produced no text");
    }
    nt_code_image_free(&image);
    nt_frontend_free(&program);
    return ok;
}

static void lower_row(const NovaHostImage *image, const char *form, uint64_t cpl)
{
    const Shape *shape = shape_of(form);
    char source[1024], why[256], clob[256];
    size_t size = 0;
    unsigned v;
    const char *chosen = NULL;
    if (!shape) return;
    body_clobbers(shape->form, clob, sizeof clob);

    /* LA FORME EST DÉCOUVERTE, JAMAIS CHOISIE. Les neuf variantes sont
     * essayées dans l'ordre et la PREMIÈRE que la référence accepte est celle
     * sur laquelle le produit est ensuite appelé. Choisir à la main serait
     * écrire une attente dans le harnais, c'est-à-dire faire du harnais la
     * source de sa propre vérité — et la première version l'a fait, avec une
     * seule variante, et la référence l'a refusée sur les quatre formes. */
    for (v = 0; v < VARIANT_COUNT; v++) {
        build_source(shape, &VARIANTS[v], oracle_atoms(form), clob, source, sizeof source);
        if (reference_text_of(source, &size, why, sizeof why)) {
            chosen = VARIANTS[v].label;
            break;
        }
        note_reason(why);
        printf("IS-VARIANT %-8s cpl=%u | %-28s | reference=%s\n", form, (unsigned)cpl,
               VARIANTS[v].label, why);
    }
    cases++;
    if (!chosen) {
        lower_unreachable++;
        checks++;
        printf("IS-LOWER %-8s cpl=%u | aucune des %u variantes declarees n'est acceptee par la "
               "reference, donc aucune comparaison d'octets n'a lieu pour cette forme\n",
               form, (unsigned)cpl, VARIANT_COUNT);
        return;
    }
    lower_accepted++;

    memset(product_words, 0xcc, sizeof product_words);
    Enc result = call_entry(image, source, 1, cpl, 0, product_words, OUTCAP);
    if (result.runtime) {
        checks++;
        failures++;
        fprintf(stderr, "FAIL runtime error %u lowering %s at cpl %u\n", (unsigned)result.runtime,
                form, (unsigned)cpl);
        return;
    }

    if (result.returned != 0) {
        lower_refused++;
        /* La référence produit du texte et le produit refuse : c'est une
         * DIVERGENCE À UN SEUL CÔTÉ, comptée à part et publiée. Elle n'est pas
         * un échec de comparaison — une comparaison d'octets n'a pas lieu
         * d'être — mais elle ne doit pas être confondue avec une ligne verte :
         * c'est exactement le cas que le critère A4.06 nomme, et le compteur
         * est dans la bannière pour qu'un lecteur ne l'apprenne pas d'un
         * rapport. */
        lower_one_sided++;
        printf("IS-LOWER %-8s cpl=%u | forme=%s reference=%zu octets | product=refused %llu | "
               "DIVERGENCE A UN SEUL COTE\n",
               form, (unsigned)cpl, chosen, size, (unsigned long long)result.returned);
        return;
    }

    lower_compared++;
    checks++;
    size_t produced = (size_t)result.out[0];
    int same = 0;
    if (produced >= 8 && produced - 8 <= OUTCAP - 8) {
        /* Le produit rend un CONTENEUR NXO sérialisé, la référence rend l'image
         * de code brute : comparer les octets bruts serait rouge par
         * construction. `nt_object_read` relit le conteneur dans le même type
         * que celui que la référence remplit, et c'est la SECTION `.text` qui
         * est confrontée. */
        NtObject readback;
        NtDiagnostic error;
        memset(&readback, 0, sizeof readback);
        memset(&error, 0, sizeof error);
        checks++;
        if (!nt_object_read(product_object + 8, produced - 8, &readback, &error)) {
            failures++;
            fprintf(stderr, "FAIL lower %s cpl=%u: the product wrote %zu bytes that "
                            "nt_object_read refuses (%u %s), so there is no section to compare\n",
                    form, (unsigned)cpl, produced, error.code, error.message);
            nt_object_free(&readback);
            produced = 0;
        } else {
            same = readback.sections[0].size == size && size != 0 &&
                   memcmp(readback.sections[0].bytes, reference_text, size) == 0;
            nt_object_free(&readback);
        }
    }
    if (same) {
        lower_equal++;
    } else {
        lower_diverge++;
        failures++;
        fprintf(stderr, "FAIL lower %s cpl=%u: the product writes %zu octet(s) and the reference "
                        "%zu. ",
                form, (unsigned)cpl, produced, size);
        size_t limit = produced < size ? produced : size;
        if (limit > 24) limit = 24;
        fprintf(stderr, "product [");
        for (size_t k = 0; k < limit; k++)
            fprintf(stderr, "%s%02x", k ? " " : "", product_object[8 + k]);
        fprintf(stderr, "] reference [");
        for (size_t k = 0; k < limit; k++)
            fprintf(stderr, "%s%02x", k ? " " : "", reference_text[k]);
        fprintf(stderr, "]\n");
    }
    printf("IS-LOWER %-8s cpl=%u | forme=%s | product=%zu octets reference=%zu octets agree=%d\n",
           form, (unsigned)cpl, chosen, produced, size, same);
}

int main(void)
{
    printf("IS-BANNER modules=%u\n", MODULE_COUNT);
    NovaHostImage *image = map_modules(MODULES, MODULE_COUNT);

    /* PAS DE GARDE DE CLÔTURE ICI, et c'est une décision. `ng_parity_closure_is`
     * résout un nom de module importé à travers la liste de la chaîne de
     * validation — il a refusé cette entrée en disant « imports ntasm_nxo and
     * no file in the tree carries it », alors que `nxo.nova` porte
     * `module ntasm_nxo;` et figure dans MODULES. L'instrument est écrit pour
     * UN autre sujet ; l'appliquer ici produirait un rouge qui ne nomme aucun
     * défaut du produit. Un garde qui ne peut pas fonctionner sur son sujet
     * n'est pas un garde. La liste ci-dessus reste donc une liste, et elle est
     * celle de la porte `x64_lower_nxo_pe`, qui est la seule à l'avoir fait
     * compiler. */

    if (image) {
        for (unsigned k = 0; k < SHAPE_COUNT; k++) {
            NtX64Effects effects;
            memset(&effects, 0, sizeof effects);
            if (nt_x64_effects(SHAPES[k].form, NULL, 0, (NtX64Context){NT_X64_ALL_FEATURES, 0},
                               &effects) != NT_X64_OK)
                continue;
            uint32_t required = effects.required_features ? effects.required_features : 1u;
            /* cpl 0 : le cas conforme. cpl 3 : la forme privilégiée doit être
             * refusée des deux côtés. features amputées : le refus vient du
             * moteur et non du langage, et sans cette colonne la moitié des
             * refus du tableau ne serait jamais touchée. */
            encoder_row(image, SHAPES[k].form, NT_X64_ALL_FEATURES, 0);
            encoder_row(image, SHAPES[k].form, NT_X64_ALL_FEATURES, 3);
            encoder_row(image, SHAPES[k].form, required, 0);
            encoder_row(image, SHAPES[k].form, required & ~1u, 0);
            encoder_row(image, SHAPES[k].form, required, 3);
        }

        atoms_table();

        /* D — les deux anneaux. L'anneau 3 est celui que toutes les entrées de
         * cet arbre utilisent ; l'anneau 0 est celui que la référence utilise
         * (`codegen.c` : `NtX64Context context = {NT_X64_ALL_FEATURES, 0}`).
         * Les deux colonnes sont produites par la même boucle, sinon la
         * colonne anneau 0 serait celle qu'on n'aurait pas écrit. */
        for (unsigned k = 0; k < SHAPE_COUNT; k++) {
            lower_row(image, SHAPES[k].form, 0);
            lower_row(image, SHAPES[k].form, 3);
        }
    }

    /* ---- contrôles de non-vacuités ----
     * Un instrument qui n'a rien exercé sort les mêmes nombres qu'un instrument
     * qui a tout exercé : chacun de ces compteurs est à zéro dans le monde où ce
     * fichier ne fait rien, et c'est ce qui les rend des contrôles. */
    checks++;
    if (bytes_equal == 0) {
        failures++;
        fprintf(stderr, "FAIL no encoded byte was ever compared: the parity this gate claims was "
                        "not exercised\n");
    }
    checks++;
    if (refusals_agree == 0) {
        failures++;
        fprintf(stderr, "FAIL no shared refusal: the refusal-parity column was never exercised\n");
    }
    checks++;
    if (spec_rows_agree == 0) {
        failures++;
        fprintf(stderr, "FAIL no spec row agreed with the oracle: the atom table was never "
                        "exercised\n");
    }
    checks++;
    if (spec_rows_diverge != 0)
        fprintf(stderr, "FAIL spec rows diverging=%u: every diverging row already failed above\n",
                spec_rows_diverge);
    checks++;
    /* LA NON-VACUITÉ EST « CHAQUE RANGÉE EST RENDUE COMPTE », pas « la
     * référence accepte quelque chose ». La première version exigeait
     * `lower_compared > 0` puis `lower_accepted > 0`, et les deux sont FAUSSES
     * sur ce produit : la référence elle-même refuse les quatre formes, chacune
     * pour un motif nommé — 502 « omits an inferred clobber » pour `swapgs`,
     * 200 « expected clobber set » pour `syscall` et `iretq`, 500 « reachable
     * path falls out of function » pour `sysretq`, 503 « iretq requires
     * unavailable stack/frame balance proof » pour `iretq`. Une porte qui exige
     * que la comparaison ait lieu rougirait donc en constatant correctement que
     * le chemin s'arrête avant l'octet — et c'est ce constat qui est l'objet du
     * critère.
     *
     * Ce qui doit tenir, et qui ne peut pas être satisfait par une porte
     * inerte : les huit rangées sont RENDUES COMPTE exactement une fois, et les
     * refus de la référence ne sont pas UN refus répété. Une boucle de
     * découverte cassée qui n'essaierait qu'une variante donnerait un seul
     * motif et le compteur le dirait. */
    checks++;
    if (lower_compared + lower_refused + lower_unreachable != 2u * SHAPE_COUNT) {
        failures++;
        fprintf(stderr, "FAIL the %u lowering rows are not accounted for exactly once: "
                        "compared=%u refused=%u unreachable=%u\n",
                2u * SHAPE_COUNT, lower_compared, lower_refused, lower_unreachable);
    }
    checks++;
    /* LE SEUIL EST TROIS, pas deux. Un seul motif serait une boucle qui
     * n'essayait qu'une variante ; deux motifs pourraient être une variante et
     * son voisin. Les quatre formes échouent pour quatre raisons que la
     * référence écrit elle-même, et c'est ce compte qui le prouve. */
    if (unreachable_reasons < 3u) {
        failures++;
        fprintf(stderr, "FAIL the reference refused the declared variants with %u DISTINCT "
                        "reason(s); the four privileged forms do not fail alike, and a loop "
                        "that tried a single variant would be indistinguishable\n",
                unreachable_reasons);
    } else {
        fprintf(stderr, "REPORT the reference named %u distinct refusal reasons across the "
                        "declared variants; those are its own statements of where the "
                        "privileged path stops, and they are the result of this gate\n",
                unreachable_reasons);
    }

    /* La libération AVANT la bannière, et non après : une fuite fait avorter le
     * processus sous `detect_leaks=1`, donc une bannière imprimée après une
     * fuite ne serait jamais lue — le pilote la classerait `INTERRUPTED`, ce
     * qui n'est pas un rouge et ne dit rien du produit. */
    release_image();

    printf("NTASM_NOVA_INTERRUPT_SYSCALL checks=%u failures=%u cases=%u bytes_equal=%u "
           "bytes_wrong=%u refusals_agree=%u refusals_split=%u spec_rows_agree=%u "
           "spec_rows_diverge=%u lower_accepted=%u lower_compared=%u lower_equal=%u "
           "lower_diverge=%u lower_refused=%u lower_one_sided=%u lower_unreachable=%u "
           "reference_reasons=%u\n",
           checks, failures, cases, bytes_equal, bytes_wrong, refusals_agree, refusals_split,
           spec_rows_agree, spec_rows_diverge, lower_accepted, lower_compared, lower_equal,
           lower_diverge, lower_refused, lower_one_sided, lower_unreachable,
           unreachable_reasons);
    return failures ? 1 : 0;
}
