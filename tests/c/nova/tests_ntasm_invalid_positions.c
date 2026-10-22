/* A4.01 — « Cas invalides refusés avec positions », mesuré sur le PARCOURS
 * COMPLET et non sur une passe isolée.
 *
 * =========================== CE QUE CETTE PORTE CHANGE =========================
 *
 * Les quatre portes A4 existantes — `effects`, `clobbers`, `contracts`, `abi` —
 * affirment toutes la même chose, et toutes les quatre l'affirment de la même
 * façon :
 *
 *   effects  : bad |= result.out[0]==guard || result.out[1]==guard
 *   clobbers : (!untouched && r.out[0]==guard)
 *   contracts: r.out[0]==guard || r.out[1]==guard || r.out[2]!=a
 *   abi      : idem
 *
 * Toutes ces lignes sont satisfaites par (0,0), par (1,1) et par la bonne
 * réponse indifféremment. Une passe qui aurait publié la position du MOT-CLÉ
 * `effects` pour un effet inconnu serait restée verte. C'est une lacune
 * d'INSTRUMENT qui revendique une couverture : la moitié du critère écrite dans
 * le document n'était mesurée par aucun instrument.
 *
 * Cette porte mesure trois choses que les quatre autres ne mesurent pas :
 *
 *   1. LE PARCOURS. Elle appelle `validate.validate`, qui enchaîne les étapes
 *      de spec/ntasm/ntasm.md 17.7. C'est le code que voit l'utilisateur, pas la
 *      passe isolée qu'un harnais peut appeler. Entre la passe et l'utilisateur
 *      il y a trente étapes et une branche d'erreur qui republie un mot du
 *      tampon.
 *
 *   2. LA POSITION CONTRE L'AUTRE MOITIÉ. `nt_frontend_compile` est appelé sur
 *      la MÊME source, dans le MÊME processus, et sa première diagnostique est
 *      PUBLIÉE en regard de celle du produit, ligne par ligne. Elle n'est PAS
 *      assertée : la spécification documente des divergences réelles entre les
 *      deux côtés, et une porte qui exigeait la parité serait rouge sur une
 *      divergence documentée — ce qui est indistinguishable d'une porte rouge
 *      pour une raison vraie. La parité est donc un COMPTE et non un verdict,
 *      et c'est dit ici parce qu'un bandeau qui annonce une mesure doit la
 *      mesurer : `agree`, `diverge` et `same_code` sont publiés, et la propriété
 *      que cette porte ASSERTE est aux points 1, 3 et 4.
 *
 *   3. LA POSITION EST VIVANTE SUR LES DEUX AXES. Deux perturbations
 *      orthogonales par fixture : UNE ligne de commentaire insérée devant la
 *      queue, qui doit décaler la ligne publiée de 1 et laisser la colonne ; et
 *      K espaces en tête de chaque ligne de la queue, qui doit décaler la
 *      COLONNE de K et laisser la ligne. K varie d'une rangée à l'autre.
 *      Une seule des deux laisserait passer un produit qui publie `(4, 7)` pour
 *      toutes ses rangées. Les deux ensemble, non.
 *
 *   4. LE CODE, pas seulement le refus. Chaque rangée porte le numéro que la
 *      table §17.6 attribue au refus, et une rangée dont le produit publie un
 *      AUTRE code échoue : un refus avec le bon numéro et la mauvaise règle
 *      n'est pas le refus que la règle décrit.
 *
 * ============================ LE 800 SANS POSITION =============================
 *
 * `validate.validate` renvoie 800 SANS ÉCRIRE dans `out` quand l'arbre est
 * invalide ou quand `out` est trop court : un 800 transactionnel ne porte pas de
 * position, PAR CONSTRUCTION de son type de retour. C'est une autre question que
 * « la position est-elle juste », et ce n'est pas ce que cette porte mesure : une
 * rangée qui rend 800 est rouge ici, avec le motif nommé, parce que le critère
 * demande un refus AVEC position et qu'un refus sans position n'en est pas un.
 * Ce qui n'est pas mesuré ici — réserve nommée, pas défaut de cet instrument —
 * c'est le canal d'abaissement, dont le type de retour `WriteResult { code,
 * bytes }` n'a aucun champ où une position pourrait vivre.
 */
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include "../../../compiler/c/ntasm/frontend/frontend.h"
#include "ntasm_pipeline_parity.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* La liste des modules de la chaîne complète n'est PAS recopiée ici. Elle vit
 * dans l'entête partagé `nova/ntasm_pipeline_parity.h`, qui la tient et qui la
 * confronte à la CLÔTURE DES IMPORTS lue dans l'arbre : quarante-trois chemins
 * écrits dans ce fichier seraient une transcription, et une transcription se
 * périme sans bruit. `ng_parity_closure_is` est l'instrument qui la garde —
 * sans lui, un module ajouté à `validate.nova` produirait ici un E302 que
 * personne n'aurait cherché. */

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

typedef struct {
    uint64_t returned, runtime, out[6];
} Run;

static Run product(const NovaHostImage *image, const char *source)
{
    static const uint64_t guard = UINT64_C(0xcccccccccccccccc);
    Run result;
    NovaContextV2 context = {0};
    unsigned k;
    for (k = 0; k < 6; k++) result.out[k] = guard;
    result.returned = guard;
    result.runtime = guard;
    if (!nova_context_init_v2(&context)) return result;
    uint64_t source_handle = nova_borrow_v2(&context, (void *)source, strlen(source), 0);
    uint64_t out_handle = nova_borrow_v2(&context, result.out, sizeof result.out, 1);
    uint64_t args[] = {source_handle, strlen(source), out_handle, 6};
    result.returned = image->entry(&context, args, 4);
    result.runtime = context.error;
    (void)nova_context_destroy_v2(&context);
    return result;
}

typedef struct {
    int accepted;
    unsigned code;
    uint32_t line, column;
    char message[192];
} Oracle;

static Oracle oracle(const char *source)
{
    Oracle result;
    NtFInput input = {"m", source, strlen(source)};
    NtFProgram program;
    memset(&result, 0, sizeof result);
    memset(&program, 0, sizeof program);
    result.line = UINT32_MAX;
    result.column = UINT32_MAX;
    if (nt_frontend_compile(&input, 1, &program)) {
        result.accepted = 1;
        snprintf(result.message, sizeof result.message, "%s", "accepte");
    } else if (program.diagnostic_count) {
        result.code = program.diagnostics[0].code;
        result.line = program.diagnostics[0].span.line;
        result.column = program.diagnostics[0].span.column;
        snprintf(result.message, sizeof result.message, "%s", program.diagnostics[0].message);
    } else {
        snprintf(result.message, sizeof result.message, "%s", "refus sans diagnostique");
    }
    nt_frontend_free(&program);
    return result;
}

/* ------------------------------------------------------------------------- *
 * La table. `head` et `tail` séparent la ligne fautive du reste : la ligne
 * fautive est la PREMIÈRE de `tail`, donc insérer une ligne entre les deux
 * déplace exactement la position publiée d'une unité et laisse la colonne.
 * C'est ce qui rend le contrôle de propagation arithmétique.
 *
 * `rule_code` est le numéro que la table §17.6 de spec/ntasm/ntasm.md attribue au
 * refus, lu dans le document et non dans le produit. `accepted` marque les
 * lignes où les deux côtés doivent ACCEPTER : sans elles, une porte qui refuse
 * tout passe aussi bien qu'une porte qui refuse juste.
 * `why` est la règle que la ligne exerce, et elle est imprimée : une rangée sans
 * motif nommé n'est pas une couverture, c'est un nombre.
 */
typedef struct {
    const char *label;
    const char *head;
    const char *tail;
    unsigned rule_code;
    int accepted;
    const char *why;
} Row;

static const char *const HEAD_PLAIN =
    "module m\n"
    "target x86_64-nexora-none\n"
    "section .text {\n";

static const Row ROWS[] = {
    {"effects-321-unknown", HEAD_PLAIN,
     "fn f()->u64\neffects {telepathy}\nclobbers {} {\nreturn 0\n}\n}\n",
     321, 0, "spec 17.6 : `321` raison 1 nom d'effet inconnu"},
    {"effects-321-atom-argument", HEAD_PLAIN,
     "fn f()->u64\neffects {privileged(user)}\nclobbers {} {\nreturn 0\n}\n}\n",
     321, 0, "spec 17.6 : `321` raison 2 argument sur un atome"},
    {"effects-321-space", HEAD_PLAIN,
     "fn f()->u64\neffects {reads_mem(telepathy)}\nclobbers {} {\nreturn 0\n}\n}\n",
     321, 0, "spec 17.6 : `321` raison 3 espace mémoire hors catalogue"},
    {"effects-322-duplicate", HEAD_PLAIN,
     "fn f()->u64\neffects {msr,msr}\nclobbers {} {\nreturn 0\n}\n}\n",
     322, 0, "spec 8.1 : « Un set refuse deux occurrences sémantiquement identiques »"},
    {"clobbers-320-duplicate", HEAD_PLAIN,
     "fn f()->u64\neffects {}\nclobbers {rax,rax} {\nreturn 0\n}\n}\n",
     320, 0, "spec 17.6 : `320` second nom d'une même famille physique"},
    {"clobbers-330-unknown", HEAD_PLAIN,
     "fn f()->u64\neffects {}\nclobbers {foo} {\nreturn 0\n}\n}\n",
     330, 0, "spec 17.6 : `330` nom de registre inconnu ou qualifié"},
    {"clobbers-330-qualified", HEAD_PLAIN,
     "fn f()->u64\neffects {}\nclobbers {cpu.rax} {\nreturn 0\n}\n}\n",
     330, 0, "spec 17.6 : `330` — « nom de registre inconnu ou qualifié », à la ligne et colonne de ce nom"},
    {"contracts-323-unknown", HEAD_PLAIN,
     "fn f()->u64\neffects {}\nclobbers {}\nrequires {telepathy(1)} {\nreturn 0\n}\n}\n",
     323, 0, "spec 17.6 : `323` raison 1 nom de prédicat hors catalogue"},
    {"contracts-323-qualified", HEAD_PLAIN,
     "fn f()->u64\neffects {}\nclobbers {}\nrequires {cpu.feature(sse2)} {\nreturn 0\n}\n}\n",
     323, 0, "spec 17.6 : `323` raison 2 nom qualifié"},
    {"contracts-324-short-arity", HEAD_PLAIN,
     "fn f()->u64\neffects {}\nclobbers {}\nrequires {feature()} {\nreturn 0\n}\n}\n",
     324, 0, "spec 17.3 : `feature(x)` est d'arité 1"},
    {"contracts-324-long-arity", HEAD_PLAIN,
     "fn f()->u64\neffects {}\nclobbers {}\nrequires {interrupts_enabled(1)} {\nreturn 0\n}\n}\n",
     324, 0, "spec 17.3 : `interrupts_enabled()` est d'arité 0"},
    {"abi-328-out-family-in-clobbers", HEAD_PLAIN,
     "fn f(out q:u64 @rdx)->u64\neffects {}\nclobbers {rdx} {\nreturn 0\n}\n}\n",
     328, 0, "spec 17.5 : une famille de sortie ne peut figurer dans `clobbers`"},
    {"calls-310-unknown-callee", HEAD_PLAIN,
     "fn f()->u64\neffects {}\nclobbers {} {\ncall nowhere()\nreturn 0\n}\n}\n",
     310, 0, "spec 17.6 : `310` — « ligne et colonne du premier nom de callee absent »; `311` est réservé au désaccord d'ARITÉ"},
    {"abi-329-out-not-integer", HEAD_PLAIN,
     "fn f(out a:bool @al)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n",
     329, 0, "spec 17.6 : `329` raison 1 — un `out` doit être un entier machine OU un pointeur; `bool` n'est ni l'un ni l'autre"},
    /* ---- les lignes qui doivent être ACCEPTÉES par les deux côtés ---- */
    {"accepted-plain", HEAD_PLAIN,
     "fn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n",
     0, 1, "un module valide : sans cette ligne, « tout est refusé » passerait"},
    {"accepted-effects", HEAD_PLAIN,
     "fn f()->u64\neffects {privileged,changes_flags,msr,control}\nclobbers {} {\nreturn 0\n}\n}\n",
     0, 1, "quatre atomes du vocabulaire de spec 8.1"},
    {"accepted-predicates",
     "module m\n"
     "target x86_64-nexora-none\n"
     "section .text {\n",
     "fn f(in p:ptr<user,u64> @rdi)->u64\neffects {}\nclobbers {}\n"
     "requires {non_null(p),canonical(p),stack_aligned(16)}\nensures {canonical(p)} {\nreturn 0\n}\n}\n",
     0, 1, "trois prédicats du catalogue de spec 17.3, en requires et en ensures"},
    {"accepted-clobbers", HEAD_PLAIN,
     "fn f()->u64\neffects {}\nclobbers {rax,rcx,rflags} {\nreturn 0\n}\n}\n",
     0, 1, "trois noms du catalogue target, dont rflags"},
    /* ---- le chemin interruption/syscall : un atome de moins, un refus ----
     *
     * Le code 334 est celui que la table §17.6 de spec/ntasm/ntasm.md attribue à
     * `body_intrinsics.check`, qui publie en `out[2]` la catégorie 1 et en
     * `out[3]` le BITSET des atomes EXIGÉS ET NON DÉCLARÉS. Ce n'est donc pas
     * seulement « la forme a été refusée » : le refus NOMME l'atome manquant,
     * et c'est ce que la colonne `missing` de `BITS` exige.
     *
     * Les deux formes `syscall` et `sysretq` sont écrites dans la forme
     * LITTÉRALE que la porte voisine `tests_ntasm_body_intrinsics.c` prouve
     * déjà — même `target`, même `clobbers {rcx,r11}`, même `return 0`, même
     * `-> never`. Une fixture inventée dont le produit refuse pour une autre
     * raison est une porte rouge pour une raison étrangère à son objet.
     *
     * `swapgs` et `iretq` n'ont AUCUNE fixture 334 dans cette porte voisine :
     * `swapgs` n'y apparaît que dans un balayage RFLAGS, jamais comme cas 334.
     * Ces quatre rangées sont donc NOUVELLES, et elles le disent : elles
     * sront les premières à dire ce que le produit fait de ces deux formes.
     */
    {"intr-334-swapgs-no-privileged", HEAD_PLAIN,
     "fn f()->u64\neffects {control}\nclobbers {} {\nswapgs\nreturn 0\n}\n}\n",
     334, 0, "§8.1 : « `swapgs`, les control registers et les opérations de descripteurs exigent `privileged` et `control` » — `privileged` manque. AUCUNE fixture 334 pour `swapgs` n'existe dans la porte voisine : cette rangée est nouvelle"},
    {"intr-334-swapgs-no-control", HEAD_PLAIN,
     "fn f()->u64\neffects {privileged}\nclobbers {} {\nswapgs\nreturn 0\n}\n}\n",
     334, 0, "§8.1 : même phrase — `control` manque. Rangée nouvelle"},
    {"intr-334-syscall-no-control", HEAD_PLAIN,
     "fn f()->u64\neffects {changes_flags}\nclobbers {rcx,r11} {\nsyscall\nreturn 0\n}\n}\n",
     334, 0, "§8.1 : « `syscall` exige `control` et `changes_flags` » — `control` manque"},
    {"intr-334-syscall-no-changes-flags", HEAD_PLAIN,
     "fn f()->u64\neffects {control}\nclobbers {rcx,r11} {\nsyscall\nreturn 0\n}\n}\n",
     334, 0, "§8.1 : « `syscall` exige `control` et `changes_flags` » — `changes_flags` manque. C'est la fixture que la porte voisine nomme « syscall flags »"},
    {"intr-334-sysretq-no-no-return", HEAD_PLAIN,
     "fn f()->never\neffects {privileged,changes_flags,control}\nclobbers {} {\nsysretq\n}\n}\n",
     334, 0, "§8.1 : `sysretq` ajoute `privileged`, `control`, `changes_flags` et `no_return` — `no_return` manque. C'est la fixture que la porte voisine nomme « sysret no return »"},
    {"intr-334-sysretq-no-privileged", HEAD_PLAIN,
     "fn f()->never\neffects {control,changes_flags,no_return}\nclobbers {} {\nsysretq\n}\n}\n",
     334, 0, "§8.1 : même phrase — `privileged` manque. Rangée nouvelle"},
    {"intr-334-iretq-no-control", HEAD_PLAIN,
     "fn f()->never\neffects {privileged,changes_flags,no_return}\nclobbers {rsp} {\niretq\n}\n}\n",
     334, 0, "§8.1 : `iretq` ajoute `privileged`, `control`, `changes_flags` et `no_return` — `control` manque. `clobbers {rsp}` parce que `registers_written` de la référence publie le bit 4 pour cette forme. AUCUNE fixture 334 pour `iretq` dans la porte voisine : rangée nouvelle"},
    {"intr-334-iretq-no-privileged", HEAD_PLAIN,
     "fn f()->never\neffects {control,changes_flags,no_return}\nclobbers {rsp} {\niretq\n}\n}\n",
     334, 0, "§8.1 : même phrase — `privileged` manque. Rangée nouvelle"},
};
#define ROW_COUNT ((unsigned)(sizeof ROWS / sizeof *ROWS))

/* Le BITSET que le refus 334 doit publier, dans la numérotation du PRODUIT
 * (`effects.nova`, ancre « fn atom_kind(source:buf<u8>,start:u64,end:u64)->u64 » :
 * privileged=1, changes_flags=2, control=32, no_return=128). Exiger le bitset
 * est plus fort qu'exiger le code : le refus doit NOMMER l'atome manquant, et
 * un produit qui refuse 334 en publiant un bitset nul ou le masque complet
 * passerait un contrôle qui ne regarde que le code.
 *
 * Les valeurs sont LUES, pas déduites : la porte voisine `tests_ntasm_body_
 * intrinsics.c` publie `out[3]=2` pour sa rangée « syscall flags » et `out[3]
 * =128` pour sa rangée « sysret no return », et ces deux nombres sont repris
 * ici tels quels. Les six autres rangées n'ont pas de contrepartie mesurée :
 * elles le sont par la MÊME numérotation, et c'est pourquoi elles sont les
 * premières à pouvoir la mettre en défaut. */
static const struct { const char *label; uint64_t bits; } BITS[] = {
    {"intr-334-swapgs-no-privileged", 1},
    {"intr-334-swapgs-no-control", 32},
    {"intr-334-syscall-no-control", 32},
    {"intr-334-syscall-no-changes-flags", 2},
    {"intr-334-sysretq-no-no-return", 128},
    {"intr-334-sysretq-no-privileged", 1},
    {"intr-334-iretq-no-control", 32},
    {"intr-334-iretq-no-privileged", 1}};
#define BIT_COUNT ((unsigned)(sizeof BITS / sizeof *BITS))

/* Zéro signifie « cette rangée ne publie pas de bitset », donc on ne l'affirme
 * pas. Une rangée absente de la table n'est pas une rangée silencieuse : elle
 * est comptée dans `bits_undeclared` et ce compte est dans le bandeau. */
static int bits_of(const char *label, uint64_t *bits)
{
    for (unsigned k = 0; k < BIT_COUNT; k++)
        if (!strcmp(BITS[k].label, label)) {
            *bits = BITS[k].bits;
            return 1;
        }
    return 0;
}
static unsigned bits_checked, bits_undeclared;

static char *join(const char *head, const char *tail)
{
    size_t hn = strlen(head), tn = strlen(tail);
    char *text = malloc(hn + tn + 1);
    if (!text) return NULL;
    memcpy(text, head, hn);
    memcpy(text + hn, tail, tn + 1);
    return text;
}

static char *with_shift(const char *head)
{
    size_t hn = strlen(head);
    char *text = malloc(hn + 10);
    if (!text) return NULL;
    memcpy(text, head, hn);
    memcpy(text + hn, "// shift\n", 10);
    return text;
}

/* La DEUXIÈME perturbation, orthogonale à la première : K espaces en tête de
 * CHAQUE ligne de la queue. Elle déplace toutes les colonnes de K et ne
 * déplace aucune ligne.
 *
 * Pourquoi il en faut deux. Une position qui n'est lue nulle part ne bouge ni
 * ligne ni colonne ; une ligne publiée en dur ne bouge pas avec l'insertion
 * d'une ligne ; une colonne publiée en dur ne bouge pas avec K. Le contrôle de
 * ligne seul laisse donc passer un produit qui publie `(4, 7)` pour toutes ses
 * rangées. Avec les deux, un produit qui publie une paire constante est rouge,
 * et un produit qui publie un compteur qui avance toujours de la même façon
 * l'est aussi.
 *
 * K varie d'une rangée à l'autre, sinon « la colonne suit K » pourrait être
 * satisfait par une colonne qui vaut `1 + K` quel que soit le K demandé. */
static char *indent_tail(const char *tail, unsigned k)
{
    size_t len = strlen(tail), at = 0, i;
    char *text = malloc(len * (k + 1) + k + 2);
    if (!text) return NULL;
    /* Les K espaces vont AU DÉBUT de chaque ligne, pas à la fin. La première
     * version les écrivait juste AVANT chaque `\n`, donc en FIN de ligne : les
     * colonnes des lignes de la queue ne bougeaient pas d'un cran et les
     * vingt-deux rangées ont été rouges sur une perturbation qui ne perturbait
     * rien. Un instrument rouge pour la raison qu'il a lui-même introduite est
     * la pire des deux, parce que la ligne de motif nomme le produit et que le
     * défaut est dans la sonde. La dernière ligne reçoit ses K espaces aussi. */
    for (unsigned w = 0; w < k; w++) text[at++] = ' ';
    for (i = 0; i < len; i++) {
        text[at++] = tail[i];
        if (tail[i] == '\n')
            for (unsigned w = 0; w < k; w++) text[at++] = ' ';
    }
    text[at] = 0;
    return text;
}

static unsigned compared, agree, diverge, same_code, moved, unmoved, accepted_rows;
static unsigned col_moved, col_unmoved;

static void measure(const NovaHostImage *image, const Row *row, unsigned index)
{
    unsigned k = 1u + (index % 5u);
    char *base = join(row->head, row->tail);
    char *shifted_head = with_shift(row->head);
    char *shifted = shifted_head ? join(shifted_head, row->tail) : NULL;
    char *indented = indent_tail(row->tail, k);
    char *spread = indented ? join(row->head, indented) : NULL;
    free(shifted_head);
    free(indented);
    if (!base || !shifted || !spread) {
        fprintf(stderr, "FAIL allocation for %s\n", row->label);
        failures++;
        free(base);
        free(shifted);
        free(spread);
        return;
    }

    Run p = product(image, base);
    Run s = product(image, shifted);
    Run q = product(image, spread);
    Oracle o = oracle(base);
    cases++;

    if (p.runtime || s.runtime || q.runtime) {
        fprintf(stderr, "FAIL runtime error on %s: %llu/%llu/%llu\n", row->label,
                (unsigned long long)p.runtime, (unsigned long long)s.runtime,
                (unsigned long long)q.runtime);
        failures++;
    }

    if (row->accepted) {
        accepted_rows++;
        checks++;
        if (p.returned != 0 || o.accepted == 0) {
            failures++;
            fprintf(stderr, "FAIL %s must be ACCEPTED by both sides and the product "
                            "refused %llu, the reference %s (%s)\n",
                    row->label, (unsigned long long)p.returned,
                    o.accepted ? "nothing" : "a diagnostic", o.message);
        }
        printf("IP-ROW %-32s ACCEPTED product=0 oracle=ACCEPT | %s\n", row->label, row->why);
        free(base);
        free(shifted);
        free(spread);
        return;
    }

    /* --- le refus porte-t-il le code que la règle lui attribue ? --- */
    checks++;
    if (p.returned != row->rule_code) {
        failures++;
        fprintf(stderr, "FAIL %s: the specification gives this refusal %u and the product "
                        "published %llu. A wrong code is a wrong refusal, and a gate that "
                        "only checked non-zero would have passed it.\n",
                row->label, row->rule_code, (unsigned long long)p.returned);
    }


    /* --- le refus NOMME-T-IL l'atome manquant ? --- */
    {
        uint64_t want = 0;
        if (bits_of(row->label, &want)) {
            bits_checked++;
            checks++;
            if (p.out[3] != want) {
                failures++;
                fprintf(stderr, "FAIL %s: the specification requires the missing atom to be "
                                "NAMED, and out[3] carries %llu where %llu is the bit of the atom "
                                "that is missing. A refusal that does not say which obligation it "
                                "found is not a refusal the caller can act on.\n",
                        row->label, (unsigned long long)p.out[3], (unsigned long long)want);
            }
        } else if (row->rule_code == 334) {
            bits_undeclared++;
            failures++;
            fprintf(stderr, "FAIL %s expects 334 but declares no missing-atom bitset, so this "
                            "gate would accept a refusal that names nothing\n",
                    row->label);
        }
    }

    /* --- le refus porte-t-il une position ? --- */
    int positioned = p.out[0] != UINT64_C(0xcccccccccccccccc) && p.out[1] != UINT64_C(0xcccccccccccccccc);
    checks++;
    if (!positioned || p.out[0] == 0 || p.out[1] == 0) {
        failures++;
        fprintf(stderr, "FAIL %s: refused %llu but published position %llu:%llu. The criterion "
                        "asks for the refusal WITH its position, and this is the half the "
                        "existing gates never read.\n",
                row->label, (unsigned long long)p.returned, (unsigned long long)p.out[0],
                (unsigned long long)p.out[1]);
    }

    /* --- la position est-elle VIVANTE ? --- */
    checks++;
    int moved_ok = s.returned == p.returned && positioned &&
                   s.out[0] == p.out[0] + 1 && s.out[1] == p.out[1];
    if (moved_ok)
        moved++;
    else {
        unmoved++;
        failures++;
        fprintf(stderr, "FAIL %s: one comment line inserted before the offending line moved the "
                        "published position from %llu:%llu to %llu:%llu instead of %llu:%llu. A "
                        "position that does not move is a counter, not a reading.\n",
                row->label, (unsigned long long)p.out[0], (unsigned long long)p.out[1],
                (unsigned long long)s.out[0], (unsigned long long)s.out[1],
                (unsigned long long)p.out[0] + 1, (unsigned long long)p.out[1]);
    }

    /* --- la position est-elle VIVANTE SUR L'AUTRE AXE ? --- */
    checks++;
    int col_ok = q.returned == p.returned && positioned &&
                 q.out[0] == p.out[0] && q.out[1] == p.out[1] + k;
    if (col_ok) {
        col_moved++;
    } else {
        col_unmoved++;
        failures++;
        fprintf(stderr, "FAIL %s: %u spaces pushed in front of every line of the tail moved the "
                        "published position from %llu:%llu to %llu:%llu instead of %llu:%llu. The "
                        "line axis and the column axis are independent, and a column that answers "
                        "always the same number is a counter wearing a position.\n",
                row->label, k, (unsigned long long)p.out[0], (unsigned long long)p.out[1],
                (unsigned long long)q.out[0], (unsigned long long)q.out[1],
                (unsigned long long)p.out[0], (unsigned long long)p.out[1] + k);
    }

    /* --- la position, confrontée à l'autre moitié --- */
    if (o.accepted) {
        printf("IP-ROW %-32s product=%llu@%llu:%llu r=%llu | oracle=ACCEPT | %s\n",
               row->label, (unsigned long long)p.returned, (unsigned long long)p.out[0],
               (unsigned long long)p.out[1], (unsigned long long)p.out[2], row->why);
    } else {
        compared++;
        if ((unsigned)p.returned == o.code) same_code++;
        int same = (p.out[0] == o.line && p.out[1] == o.column);
        if (same)
            agree++;
        else
            diverge++;
        printf("IP-ROW %-32s product=%llu@%llu:%llu r=%llu | oracle=%u@%u:%u | %s%s\n",
               row->label, (unsigned long long)p.returned, (unsigned long long)p.out[0],
               (unsigned long long)p.out[1], (unsigned long long)p.out[2], o.code, o.line,
               o.column, row->why, same ? "" : "  [POSITION-DIVERGE]");
        if (!same)
            printf("IP-DIVERGE %-28s product=%llu@%llu:%llu oracle=%u@%u:%u oracle_says=%s\n",
                   row->label, (unsigned long long)p.returned, (unsigned long long)p.out[0],
                   (unsigned long long)p.out[1], o.code, o.line, o.column, o.message);
    }

    free(base);
    free(shifted);
    free(spread);
}

int main(void)
{
    char *sources[NG_PARITY_MODULES];
    NtFInput inputs[NG_PARITY_MODULES];
    unsigned i;
    int all = 1;

    for (i = 0; i < NG_PARITY_MODULES; i++) {
        size_t size = 0;
        sources[i] = load(ng_parity_paths[i], &size);
        inputs[i] = (NtFInput){ng_parity_paths[i], sources[i], size};
        if (!sources[i]) {
            all = 0;
            fprintf(stderr, "MISSING %s\n", ng_parity_paths[i]);
        }
    }
    checks++;
    if (!all) {
        fprintf(stderr, "FAIL the 43 modules of the full pass chain must load\n");
        failures++;
    }

    /* La CLÔTURE DES IMPORTS, lue dans l'arbre. C'est le garde-fou qui remplace
     * les quarante-trois lignes de transcription retirées plus haut : sans lui,
     * un module ajouté à `validate.nova` produirait ici un E302 que personne
     * n'aurait cherché, et la porte continuerait de publier ses verdicts. */
    checks++;
    {
        char why[256];
        if (!ng_parity_closure_is(NG_PARITY_ENTRY, ng_parity_paths, NG_PARITY_MODULES, why,
                                  sizeof why)) {
            failures++;
            fprintf(stderr, "FAIL the module list must be the import closure of %s: %s\n",
                    NG_PARITY_ENTRY, why);
        }
    }
    /* L'ARTEFACT ET L'IMAGE SONT DÉCLARÉS ICI et non dans le bloc qui les
     * construit, pour une raison mesurée : le run est exécuté sous
     * `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1`, et une fuite n'a pas
     * dINCIDENT : elle ABORT le processus à la sortie. Une porte qui avorte
     * n'imprime pas sa bannière, et le pilote classe alors `INTERRUPTED` — ce
     * qui n'est pas un rouge et ne dit rien du produit. C'est ce qu'a fait la
     * première passe : dix-sept mégaoctats retenus par `codegen.c`, aucune
     * bannière, et vingt-trois lignes FAIL qui étaient toutes celles de
     * l'instrument. L'ordre de libération est celui de la porte `validate` :
     * démonter, rendre l'artefact, rendre les sources. */
    {
        NtArtifact artifact = {0};
        NovaHostImage image = {0};
        int compiled = 0;
        if (all) {
            compiled = nova_compile_many_v2(inputs, NG_PARITY_MODULES, &artifact);
            checks++;
            if (!compiled) {
                failures++;
                fprintf(stderr, "FAIL the 43 modules of the full pass chain must compile: %u "
                                "%zu:%zu %s\n",
                        artifact.error.code, artifact.error.line, artifact.error.column,
                        artifact.error.message);
            }
            checks++;
            if (!(compiled && nova_host_map(&artifact, &image))) {
                failures++;
                fprintf(stderr, "FAIL the full pass chain must map\n");
            } else {
                for (i = 0; i < ROW_COUNT; i++) measure(&image, &ROWS[i], i);
            }
        }
        if (image.memory) nova_host_unmap(&image);
        if (compiled) nt_artifact_free(&artifact);
    }
    for (i = 0; i < NG_PARITY_MODULES; i++) free(sources[i]);

    /* ---- LES TROIS CONTRES DE NON-VACUITÉ ----
     *
     * Un instrument qui n'a rien exercé sort les mêmes nombres qu'un instrument
     * qui a tout exercé. Chacun des trois compteurs ci-dessous est à zéro dans
     * le monde où ce fichier ne fait rien, et c'est ce qui les rend des
     * contrôles et pas des décorations. */
    cases++;
    checks++;
    if (compared == 0) {
        failures++;
        fprintf(stderr, "FAIL no row was compared against the reference, so the position parity "
                        "this gate claims to measure was never exercised\n");
    }
    cases++;
    checks++;
    if (moved == 0) {
        failures++;
        fprintf(stderr, "FAIL no position moved under a one line displacement, so the propagation "
                        "control was never exercised\n");
    }
    cases++;
    checks++;
    if (accepted_rows == 0) {
        failures++;
        fprintf(stderr, "FAIL no accepted row: a gate that refuses everything also satisfies every "
                        "refusal assertion here\n");
    }
    cases++;
    checks++;
    if (unmoved != 0) {
        /* le compte est-il seulement le même que le nombre de lignes ? non : il
         * doit être zéro, sinon chaque ligne immobile a déjà rendu son FAIL */
        fprintf(stderr, "FAIL unmoved=%u: every immobile position already failed its own line\n",
                unmoved);
    }
    cases++;
    checks++;
    if (col_moved == 0) {
        failures++;
        fprintf(stderr, "FAIL no published column moved under the indentation perturbation, so "
                        "the column axis of this gate was never exercised\n");
    }
    cases++;
    checks++;
    if (col_unmoved != 0)
        fprintf(stderr, "FAIL col_unmoved=%u: every immobile column already failed its own line\n",
                col_unmoved);
    cases++;
    checks++;
    if (bits_checked == 0) {
        failures++;
        fprintf(stderr, "FAIL no refusal was checked for naming its missing atom, so the bitset "
                        "half of this gate was never exercised\n");
    }
    cases++;
    checks++;
    if (bits_undeclared != 0)
        fprintf(stderr, "FAIL 334 rows with no declared bitset=%u: each already failed its own line\n",
                bits_undeclared);

    printf("NTASM_NOVA_INVALID_POSITIONS checks=%u failures=%u cases=%u compared=%u "
           "agree=%u diverge=%u same_code=%u moved=%u unmoved=%u col_moved=%u col_unmoved=%u "
           "accepted=%u bits_checked=%u bits_undeclared=%u\n",
           checks, failures, cases, compared, agree, diverge, same_code, moved, unmoved, col_moved,
           col_unmoved, accepted_rows, bits_checked, bits_undeclared);
    return failures ? 1 : 0;
}
