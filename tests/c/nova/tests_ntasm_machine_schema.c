/* BOOTSTRAP_C_TEST — A7.02, schéma Machine IR (coordinateur Claude, 4 octobre 2026). CANDIDAT :
 * nom réservé auprès de Codex, propriétaire de machine_ir.nova (out/a7-finish-20261004).
 *
 * Deux lectures du même fait, désaccordées exprès (AGENTS.md) :
 *   - le DOCUMENT spec/formats/machine-ir-v0.md, lu par ses tableaux ;
 *   - le MODULE machine_ir.nova, interrogé par machine-schema-entry.nova (constantes, schema_field,
 *     kind_text, codes de refus, header_text), puis jugé sur des IMAGES réellement produites
 *     (parse -> ntir.build -> machine_ir.lower -> verify -> serialize).
 * Tout désaccord est un FAIL. Le document n'est pas réécrit par la porte, et un changement de
 * version ou de disposition du module doit la rougir, pas être absorbé.
 *
 * Usage, depuis la racine du dépôt qui porte machine_ir.nova :
 *   MIR_DOC=… MIR_ENTRY=… machine_schema [--dump] SOURCE.ntasm …
 * Bannière : NTASM_NOVA_MACHINE_SCHEMA checks=N failures=N cases=N */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"

static unsigned checks, failures, cases;
#define CHECK(c, ...)                                                      \
    do {                                                                   \
        checks++;                                                          \
        if (!(c)) {                                                        \
            failures++;                                                    \
            fprintf(stderr, "FAIL ");                                      \
            fprintf(stderr, __VA_ARGS__);                                  \
            fputc('\n', stderr);                                           \
        }                                                                  \
    } while (0)

static char *loadf(const char *p, size_t *n)
{
    FILE *f = fopen(p, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long l = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *b = malloc(l > 0 ? (size_t)l + 1 : 1);
    if (!b || fread(b, 1, (size_t)l, f) != (size_t)l) { fclose(f); free(b); return NULL; }
    fclose(f);
    b[l] = 0;
    *n = (size_t)l;
    return b;
}

/* ---- le module ------------------------------------------------------------------------- */
static const char *MODULES[] = {"compiler/nova/ir/machine_ir.nova", "compiler/nova/formats/ntir/ntir.nova",
                                "compiler/nova/ir/ir_image.nova",   "compiler/nova/formats/pe/pe.nova",
                                "compiler/nova/frontend/parser.nova",     "compiler/nova/frontend/lexer.nova",
                                "compiler/nova/frontend/ast.nova",        "compiler/nova/analysis/types/register_widths.nova",
                                "compiler/nova/analysis/types/pointer_spaces.nova", "compiler/nova/frontend/versions.nova"};
#define NMOD (sizeof MODULES / sizeof *MODULES)
static NovaHostImage IMG;
enum { TEXTCAP = 1 << 20, WORDS = 1 << 18 };
static uint8_t TEXT[TEXTCAP];
static uint64_t NTIR[WORDS], OUT[WORDS], REPORT[64], LEN[1];

static uint64_t ask(const char *source, uint64_t mode, uint64_t index)
{
    static char none[1];
    NovaContextV2 c = {0};
    uint64_t a[14];
    size_t sn = source ? strlen(source) : 0;
    memset(REPORT, 0, sizeof REPORT);
    LEN[0] = 0;
    nova_context_init_v2(&c);
    a[0] = nova_borrow_v2(&c, source ? (void *)source : none, sn, 0); a[1] = sn;
    a[2] = mode; a[3] = index;
    a[4] = nova_borrow_v2(&c, NTIR, sizeof NTIR, 1); a[5] = WORDS;
    a[6] = nova_borrow_v2(&c, OUT, sizeof OUT, 1); a[7] = WORDS;
    a[8] = nova_borrow_v2(&c, TEXT, TEXTCAP, 1); a[9] = TEXTCAP;
    a[10] = nova_borrow_v2(&c, LEN, sizeof LEN, 1); a[11] = 1;
    a[12] = nova_borrow_v2(&c, REPORT, sizeof REPORT, 1); a[13] = 64;
    uint64_t code = IMG.entry(&c, a, 14);
    CHECK(c.error == 0, "runtime clean (mode %" PRIu64 " index %" PRIu64 ", error %" PRIu64 ")", mode, index, c.error);
    nova_context_destroy_v2(&c);
    cases++;
    return code;
}
static const char *text_of(void)
{
    static char s[4096];
    size_t n = LEN[0] < sizeof s - 1 ? (size_t)LEN[0] : sizeof s - 1;
    memcpy(s, TEXT, n);
    s[n] = 0;
    return s;
}

/* ---- le document ----------------------------------------------------------------------- */
enum { T_CONST, T_HEADER, T_RECORD, T_KIND, T_SER_HEAD, T_SER_REC, T_REFUSAL, T_COUNT };
static const char *HEADINGS[T_COUNT] = {"## 2.", "## 3.", "## 4.", "## 5.", "## 6.", "## 7.", "## 8."};
typedef struct { char c[4][128]; } Row;
static Row ROWS[T_COUNT][128];
static unsigned NROWS[T_COUNT];

static void strip(char *s)
{
    char *b = s;
    while (*b == ' ' || *b == '`') b++;
    memmove(s, b, strlen(b) + 1);
    size_t l = strlen(s);
    while (l && (s[l - 1] == ' ' || s[l - 1] == '`')) s[--l] = 0;
}
static void parse_doc(const char *doc)
{
    int table = -1;
    const char *p = doc;
    while (*p) {
        const char *e = strchr(p, '\n');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        char line[1024];
        snprintf(line, sizeof line, "%.*s", (int)(l < 1023 ? l : 1023), p);
        if (l && line[l - 1] == '\r') line[l - 1] = 0;
        if (!strncmp(line, "## ", 3)) {
            table = -1;
            for (int t = 0; t < T_COUNT; t++)
                if (!strncmp(line, HEADINGS[t], strlen(HEADINGS[t]))) table = t;
        } else if (table >= 0 && line[0] == '|' && !strstr(line, "---") && NROWS[table] < 128) {
            Row r;
            memset(&r, 0, sizeof r);
            char *q = line + 1;
            int k = 0;
            while (k < 4 && *q) {
                char *bar = strchr(q, '|');
                if (!bar) break;
                *bar = 0;
                size_t ql = strlen(q) < 127 ? strlen(q) : 127;
                memcpy(r.c[k], q, ql);
                r.c[k][ql] = 0;
                strip(r.c[k]);
                k++;
                q = bar + 1;
            }
            /* la première ligne d'un tableau est son en-tête */
            static int seen_header[T_COUNT];
            if (!seen_header[table]) { seen_header[table] = 1; }
            else ROWS[table][NROWS[table]++] = r;
        }
        p = e ? e + 1 : p + l;
    }
}
static const Row *find(int t, int col, const char *key)
{
    for (unsigned i = 0; i < NROWS[t]; i++) if (!strcmp(ROWS[t][i].c[col], key)) return &ROWS[t][i];
    return NULL;
}
static uint64_t num(const char *s) { return strtoull(s, NULL, 0); }

static const char *CONST_NAMES[9] = {"FORMAT_MAJOR", "FORMAT_MINOR", "HEADER_WORDS", "NODE_WORDS", "KIND_BASE",
                                     "KIND_COUNT",   "SCHEMA_FIELDS", "DOMAIN_BIT", "version_pin"};
static const char *REFUSAL_NAMES[19] = {"E_TAG",   "E_HEADER", "E_KIND",  "E_LINK",   "E_SHAPE", "E_CYCLE", "E_SHARED",
                                        "E_UNREACHED", "E_TYPED", "E_ORIGIN", "E_INPUT", "E_VALUE", "E_TARGET",
                                        "E_VERSION", "E_ARITY", "E_SCALE", "E_NTIR", "E_FRAME", "E_FORM"};

/* valeur d'une étiquette « nom=valeur » dans une ligne sérialisée */
static int label_value(const char *line, const char *label, uint64_t *v)
{
    char needle[64];
    snprintf(needle, sizeof needle, " %s", label);
    const char *at = strstr(line, needle);
    if (!at) return 0;
    *v = strtoull(at + strlen(needle), NULL, 10);
    return 1;
}


/* Corpus par défaut quand la porte est lancée SANS source, comme ngbuild.sh le fait : toutes les sources
 * de examples/ntasm-v0/c-bootstrap/, triées. Une porte de routine rejoue ainsi les preuves de sérialisation
 * (remarque de Codex, 4 octobre 2026). */
#include <dirent.h>
static int cmpstr(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }
static int default_corpus(char **out, int cap)
{
    const char *dir = "examples/ntasm-v0/c-bootstrap";
    DIR *d = opendir(dir);
    int n = 0;
    for (struct dirent *e; d && (e = readdir(d)) && n < cap;) {
        size_t l = strlen(e->d_name);
        if (l > 6 && !strcmp(e->d_name + l - 6, ".ntasm")) {
            out[n] = malloc(strlen(dir) + l + 2);
            sprintf(out[n], "%s/%s", dir, e->d_name);
            n++;
        }
    }
    if (d) closedir(d);
    qsort(out, (size_t)n, sizeof *out, cmpstr);
    return n;
}

int main(int argc, char **argv)
{
    int dump = argc > 1 && !strcmp(argv[1], "--dump");
    char *corpus[256];
    int ncorpus = 0;
    for (int i = 1 + dump; i < argc && ncorpus < 256; i++) corpus[ncorpus++] = argv[i];
    int defaulted = 0;
    if (ncorpus == 0) { ncorpus = default_corpus(corpus, 256); defaulted = 1; }
    printf("CORPUS sources=%d origin=%s\n", ncorpus, defaulted ? "default examples/ntasm-v0/c-bootstrap" : "argv");
    const char *entry = getenv("MIR_ENTRY") ? getenv("MIR_ENTRY") : "tests/nova/tests/machine-schema-entry.nova";
    const char *docp = getenv("MIR_DOC") ? getenv("MIR_DOC") : "spec/formats/machine-ir-v0.md";
    NtFInput in[NMOD + 1];
    char *src[NMOD + 1];
    size_t n = 0;
    src[0] = loadf(entry, &n);
    CHECK(src[0] != NULL, "entry %s readable", entry);
    if (!src[0]) return 1;
    in[0] = (NtFInput){entry, src[0], n};
    for (unsigned i = 0; i < NMOD; i++) {
        src[i + 1] = loadf(MODULES[i], &n);
        CHECK(src[i + 1] != NULL, "module %s readable", MODULES[i]);
        if (!src[i + 1]) return 1;
        in[i + 1] = (NtFInput){MODULES[i], src[i + 1], n};
    }
    NtArtifact art = {0};
    int ok = nova_compile_many_v2(in, NMOD + 1, &art);
    CHECK(ok, "modules compile: E%u %zu:%zu %s", art.error.code, art.error.line, art.error.column, art.error.message);
    CHECK(ok && nova_host_map(&art, &IMG) && IMG.entry, "image maps");
    if (!IMG.entry) return 1;

    /* les réponses du module */
    uint64_t consts[9], refusal[19];
    CHECK(ask(NULL, 0, 0) == 0, "mode 0 answers");
    for (int i = 0; i < 9; i++) consts[i] = REPORT[i];
    for (int i = 0; i < 19; i++) refusal[i] = REPORT[9 + i];
    uint64_t HW = consts[2], NW = consts[3], KB = consts[4], KC = consts[5], SF = consts[6];
    CHECK(ask(NULL, 3, 0) == 0, "mode 3 answers");
    char tag[64];
    snprintf(tag, sizeof tag, "%s", text_of());
    if (dump) {
        printf("CONST header_text %s\n", tag);
        for (int i = 0; i < 9; i++) printf("CONST %s %" PRIu64 "\n", CONST_NAMES[i], consts[i]);
        for (uint64_t i = 0; i < SF; i++) { ask(NULL, 1, i); printf("FIELD %" PRIu64 " %s\n", i, text_of()); }
        for (uint64_t i = 1; i <= KC; i++) { ask(NULL, 2, i); printf("KIND %" PRIu64 " %" PRIu64 " %s\n", i, REPORT[0], text_of()); }
        for (int i = 0; i < 19; i++) printf("REFUSAL %" PRIu64 " %s\n", refusal[i], REFUSAL_NAMES[i]);
    }

    size_t dn = 0;
    char *doc = loadf(docp, &dn);
    CHECK(doc != NULL, "document %s readable", docp);
    if (doc) parse_doc(doc);
    for (int t = 0; t < T_COUNT; t++) CHECK(NROWS[t] > 0, "document table %s has rows", HEADINGS[t]);

    /* 2. constantes */
    const Row *r = find(T_CONST, 0, "header_text");
    CHECK(r && !strcmp(r->c[1], tag), "header_text: document %s, module %s", r ? r->c[1] : "ABSENT", tag);
    for (int i = 0; i < 9; i++) {
        r = find(T_CONST, 0, CONST_NAMES[i]);
        CHECK(r && num(r->c[1]) == consts[i], "constant %s: document %s, module %" PRIu64, CONST_NAMES[i],
              r ? r->c[1] : "ABSENT", consts[i]);
    }
    /* 3. et 4. en-tête et enregistrement, mot par mot, depuis schema_field */
    CHECK(SF == HW + NW, "SCHEMA_FIELDS %" PRIu64 " = HEADER_WORDS %" PRIu64 " + NODE_WORDS %" PRIu64, SF, HW, NW);
    CHECK(NROWS[T_HEADER] == HW, "header table rows %u, module HEADER_WORDS %" PRIu64, NROWS[T_HEADER], HW);
    CHECK(NROWS[T_RECORD] == NW, "record table rows %u, module NODE_WORDS %" PRIu64, NROWS[T_RECORD], NW);
    for (uint64_t i = 0; i < SF; i++) {
        ask(NULL, 1, i);
        int t = i < HW ? T_HEADER : T_RECORD;
        uint64_t w = i < HW ? i : i - HW;
        char key[16];
        snprintf(key, sizeof key, "%" PRIu64, w);
        r = find(t, 0, key);
        CHECK(r && !strcmp(r->c[1], text_of()), "%s word %" PRIu64 ": document %s, module %s",
              t == T_HEADER ? "header" : "record", w, r ? r->c[1] : "ABSENT", text_of());
    }
    /* 5. genres */
    CHECK(NROWS[T_KIND] == KC, "kind table rows %u, module KIND_COUNT %" PRIu64, NROWS[T_KIND], KC);
    for (uint64_t i = 1; i <= KC; i++) {
        ask(NULL, 2, i);
        char key[24];
        snprintf(key, sizeof key, "%" PRIu64, REPORT[0]);
        r = find(T_KIND, 0, key);
        CHECK(r && !strcmp(r->c[1], text_of()), "kind %s: document %s, module %s", key, r ? r->c[1] : "ABSENT", text_of());
        CHECK(REPORT[0] == KB + i - 1, "kind_at(%" PRIu64 ") = KIND_BASE + %" PRIu64, i, i - 1);
    }
    /* 8. refus */
    CHECK(NROWS[T_REFUSAL] == 19, "refusal table rows %u, entry reads 19", NROWS[T_REFUSAL]);
    for (int i = 0; i < 19; i++) {
        r = find(T_REFUSAL, 1, REFUSAL_NAMES[i]);
        CHECK(r && num(r->c[0]) == refusal[i], "%s: document %s, module %" PRIu64, REFUSAL_NAMES[i], r ? r->c[0] : "ABSENT",
              refusal[i]);
    }
    /* 6. et 7., et les images réelles */
    const Row *magic = find(T_CONST, 0, "magic");
    CHECK(magic != NULL, "document names the magic word");
    unsigned accepted = 0, refused = 0, kinds_seen = 0;
    int seen[256] = {0};
    for (int s = 0; s < ncorpus; s++) {
        size_t sn = 0;
        char *source = loadf(corpus[s], &sn);
        CHECK(source != NULL, "source %s readable", corpus[s]);
        if (!source) continue;
        uint64_t code = ask(source, 4, 0);
        if (code != 0) {
            refused++;
            printf("MIR_IMAGE %s refused=%" PRIu64 "\n", corpus[s], code);
            free(source);
            continue;
        }
        accepted++;
        uint64_t records = OUT[3];
        CHECK(magic && OUT[0] == num(magic->c[1]), "%s: word 0 0x%" PRIx64 ", document magic %s", corpus[s], OUT[0],
              magic ? magic->c[1] : "ABSENT");
        CHECK(OUT[1] == consts[0] && OUT[2] == consts[1], "%s: words 1,2 = major,minor", corpus[s]);
        r = find(T_HEADER, 1, "stride");
        CHECK(r && OUT[num(r->c[0])] == NW, "%s: the document's stride word holds NODE_WORDS", corpus[s]);
        /* la ligne d'en-tête */
        char *txt = calloc(1, (size_t)LEN[0] + 1);
        memcpy(txt, TEXT, (size_t)LEN[0]);
        char *nl = strchr(txt, '\n');
        CHECK(nl != NULL, "%s: serialization has a header line", corpus[s]);
        if (!nl) { free(txt); free(source); continue; }
        *nl = 0;
        CHECK(!strncmp(txt, tag, strlen(tag)), "%s: serialization begins with header_text %s", corpus[s], tag);
        for (unsigned i = 0; i < NROWS[T_SER_HEAD]; i++) {
            uint64_t v = 0;
            int has = label_value(txt, ROWS[T_SER_HEAD][i].c[0], &v);
            uint64_t w = num(ROWS[T_SER_HEAD][i].c[1]);
            CHECK(has && w < HW && v == OUT[w], "%s: header label %s holds word %" PRIu64, corpus[s], ROWS[T_SER_HEAD][i].c[0], w);
        }
        /* chaque ligne d'enregistrement */
        char *line = nl + 1;
        uint64_t id = 0;
        while (*line) {
            char *e = strchr(line, '\n');
            if (e) *e = 0;
            id++;
            CHECK(strtoull(line, NULL, 10) == id, "%s: record line %" PRIu64 " starts with its id", corpus[s], id);
            const uint64_t *rec = OUT + HW + (id - 1) * NW;
            for (unsigned i = 0; i < NROWS[T_SER_REC]; i++) {
                uint64_t v = 0;
                int has = label_value(line, ROWS[T_SER_REC][i].c[0], &v);
                uint64_t w = num(ROWS[T_SER_REC][i].c[1]);
                CHECK(has && w < NW && v == rec[w], "%s record %" PRIu64 ": label %s holds word %" PRIu64 " (%" PRIu64 " vs %" PRIu64 ")",
                      corpus[s], id, ROWS[T_SER_REC][i].c[0], w, v, w < NW ? rec[w] : 0);
            }
            char key[24];
            snprintf(key, sizeof key, "%" PRIu64, rec[0]);
            CHECK(find(T_KIND, 0, key) != NULL, "%s record %" PRIu64 ": kind %s is in the document", corpus[s], id, key);
            if (rec[0] >= KB && rec[0] < KB + KC && !seen[rec[0] - KB]) { seen[rec[0] - KB] = 1; kinds_seen++; }
            if (!e) break;
            line = e + 1;
        }
        CHECK(id == records, "%s: %" PRIu64 " record lines, header record_count %" PRIu64, corpus[s], id, records);
        printf("MIR_IMAGE %s accepted records=%" PRIu64 "\n", corpus[s], records);
        free(txt);
        free(source);
    }
    CHECK(accepted > 0, "PROOF_INVALID: no source produced a verified image, so the image half measured nothing");
    printf("MIR_KINDS_SEEN %u of %" PRIu64 " (not a closure: which kinds a corpus reaches is the pipeline's property)\n",
           kinds_seen, KC);
    printf("NTASM_NOVA_MACHINE_SCHEMA checks=%u failures=%u cases=%u images_accepted=%u images_refused=%u\n", checks,
           failures, cases, accepted, refused);
    free(doc);
    nova_host_unmap(&IMG);
    nt_artifact_free(&art);
    for (unsigned i = 0; i <= NMOD; i++) free(src[i]);
    if (defaulted) for (int i = 0; i < ncorpus; i++) free(corpus[i]);
    return failures != 0;
}
