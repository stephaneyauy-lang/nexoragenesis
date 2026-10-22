/* BOOTSTRAP_C_TEST — A7.09, goldens de SORTIE (coordinateur Claude, 4 octobre 2026).
 * Candidat pour tests/c/nova/tests_ntasm_output_goldens.c, non intégré.
 *
 * Pour chaque ligne de MANIFEST.tsv (membre, source, genre pe|nxo, fichier golden, sha256) :
 *   1. le golden sur disque a l'empreinte que le manifeste écrit (on ne le modifie pas en silence) ;
 *   2. la RÉFÉRENCE C, recompilée dans CE processus, écrit encore exactement ces octets
 *      (un golden périmé rougit au lieu de juger) ;
 *   3. le WRITER NOVA écrit exactement ces octets : x64_lower_nxo_pe.build_function_bodies
 *      (mode 1) pour un PE, et x64_lower_nxo.build_function_bodies (mode 2) pour un NXO.
 * Clôture de population, dans les deux sens : chaque fichier *.ntasm du répertoire des sources a
 * ses deux lignes, et chaque ligne nomme un fichier qui existe.
 * Contrôles négatifs dans le même processus : un octet du golden basculé doit être vu par la
 * comparaison ET par l'empreinte. Sinon, PROOF_INVALID.
 * Lancement depuis la racine du dépôt :
 *   GOLDENS_DIR=… output_goldens   (par défaut out/c-bootstrap/nova/goldens : AGENTS.md, binaires et preuves sous out/)
 * Bannière : NTASM_NOVA_OUTPUT_GOLDENS checks=N failures=N cases=N */
#include <dirent.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/ntasm/formats/object.h"

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

/* ---- SHA-256 (FIPS 180-4), sur octets ------------------------------------------------------ */
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
static void sha256_hex(const uint8_t *p, size_t n, char out[65])
{
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    size_t total = ((n + 9 + 63) / 64) * 64;
    for (size_t off = 0; off < total; off += 64) {
        uint8_t b[64];
        uint32_t w[64];
        for (int i = 0; i < 64; i++) {
            size_t at = off + (size_t)i;
            uint64_t bits = (uint64_t)n * 8;
            b[i] = at < n ? p[at] : at == n ? 0x80 : at >= total - 8 ? (uint8_t)(bits >> (8 * (total - 1 - at))) : 0;
        }
        for (int i = 0; i < 16; i++) w[i] = (uint32_t)b[4 * i] << 24 | (uint32_t)b[4 * i + 1] << 16 | (uint32_t)b[4 * i + 2] << 8 | b[4 * i + 3];
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t t1 = hh + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
            uint32_t t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & bb) ^ (a & c) ^ (bb & c));
            hh = g; g = f; f = e; e = d + t1; d = c; c = bb; bb = a; a = t1 + t2;
        }
        h[0] += a; h[1] += bb; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    for (int i = 0; i < 8; i++) snprintf(out + 8 * i, 9, "%08x", h[i]);
}

static uint8_t *loadf(const char *p, size_t *n)
{
    FILE *f = fopen(p, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long l = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc(l > 0 ? (size_t)l + 1 : 1);
    if (!b || fread(b, 1, (size_t)l, f) != (size_t)l) { fclose(f); free(b); return NULL; }
    fclose(f);
    b[l] = 0;
    *n = (size_t)l;
    return b;
}

/* ---- la référence C, dans ce processus ---------------------------------------------------- */
static int c_reference(const char *path, const char *kind, uint8_t **out, size_t *n)
{
    size_t sn = 0;
    char *src = (char *)loadf(path, &sn);
    if (!src) return 0;
    NtFInput in = {path, src, sn};
    int ok = 0;
    if (!strcmp(kind, "pe")) {
        NtArtifact a = {0};
        ok = nt_compile_many(&in, 1, &a) && nt_make_pe(&a);
        if (ok) { *n = a.pe.size; *out = malloc(*n ? *n : 1); memcpy(*out, a.pe.bytes, *n); }
        nt_artifact_free(&a);
    } else {
        NtObject o = {0};
        NtBuffer e = {0};
        NtDiagnostic d = {0};
        ok = nt_object_compile(&in, 1, &o, &d) && nt_object_write(&o, &e, &d);
        if (ok) { *n = e.size; *out = malloc(*n ? *n : 1); memcpy(*out, e.bytes, *n); }
        free(e.bytes);
        nt_object_free(&o);
    }
    free(src);
    return ok;
}

/* ---- le writer Nova --------------------------------------------------------------------- */
static const char *PATHS[] = {
    "tests/nova/tests/x64-lower-nxo-pe-entry.nova", "compiler/nova/backend/x64/x64_lower_nxo_pe.nova",
    "compiler/nova/backend/x64/x64_lower_nxo.nova", "compiler/nova/backend/x64/x64_lower_control.nova",
    "compiler/nova/backend/x64/x64_lower_fixed.nova", "compiler/nova/backend/x64/x64_fixed.nova",
    "compiler/nova/analysis/types/register_widths.nova", "compiler/nova/formats/nxo/nxo_link_pe.nova",
    "compiler/nova/formats/nxo/nxo_merge.nova", "compiler/nova/formats/nxo/nxo_pe.nova", "compiler/nova/formats/nxo/nxo.nova",
    "compiler/nova/formats/pe/pe.nova", "compiler/nova/frontend/parser.nova", "compiler/nova/frontend/ast.nova",
    "compiler/nova/frontend/lexer.nova", "compiler/nova/macros/macro_splice.nova",
    "compiler/nova/macros/macro_expand.nova", "compiler/nova/macros/constant_eval.nova"};
#define NPATHS (sizeof PATHS / sizeof *PATHS)
enum { OUTCAP = 1 << 20 };

static int nova_writer(const NovaHostImage *img, const char *path, const char *kind, uint8_t **out, size_t *n,
                       uint64_t *code)
{
    size_t sn = 0;
    char *src = (char *)loadf(path, &sn);
    static uint8_t nothing[1];
    if (!src) return 0;
    uint8_t *buf = calloc(1, OUTCAP + 8);
    NovaContextV2 c = {0};
    uint64_t args[9];
    nova_context_init_v2(&c);
    args[0] = nova_borrow_v2(&c, src, sn, 0); args[1] = sn;
    args[2] = nova_borrow_v2(&c, nothing, 0, 0); args[3] = 0;
    args[4] = !strcmp(kind, "pe") ? 1 : 2;
    args[5] = nova_borrow_v2(&c, nothing, 0, 0); args[6] = 0;
    args[7] = nova_borrow_v2(&c, buf, OUTCAP + 8, 1); args[8] = OUTCAP + 8;
    *code = img->entry(&c, args, 9);
    int ok = *code == 0 && c.error == 0;
    if (c.error) *code = 1000000 + c.error;
    nova_context_destroy_v2(&c);
    uint64_t size = 0;
    memcpy(&size, buf, 8);
    if (ok && size <= OUTCAP) { *n = size; *out = malloc(size ? size : 1); memcpy(*out, buf + 8, size); }
    else ok = 0;
    free(buf);
    free(src);
    return ok;
}

static int same(const uint8_t *a, size_t an, const uint8_t *b, size_t bn) { return an == bn && !memcmp(a, b, an); }

int main(void)
{
    const char *gdir = getenv("GOLDENS_DIR") ? getenv("GOLDENS_DIR") : "out/c-bootstrap/nova/goldens";
    const char *srcdir = "examples/ntasm-v0/c-bootstrap";
    char path[1024], line[2048];
    /* le writer Nova, compilé une fois */
    NtFInput in[NPATHS];
    char *srcs[NPATHS];
    for (unsigned i = 0; i < NPATHS; i++) {
        size_t n = 0;
        srcs[i] = (char *)loadf(PATHS[i], &n);
        CHECK(srcs[i] != NULL, "Nova module %s readable", PATHS[i]);
        if (!srcs[i]) return 1;
        in[i] = (NtFInput){PATHS[i], srcs[i], n};
    }
    NtArtifact art = {0};
    NovaHostImage img = {0};
    int compiled = nova_compile_many_v2(in, NPATHS, &art);
    CHECK(compiled, "Nova writer modules compile (E%u %s)", art.error.code, art.error.message);
    CHECK(compiled && nova_host_map(&art, &img) && img.entry, "Nova writer image maps");
    if (!img.entry) return 1;

    snprintf(path, sizeof path, "%s/MANIFEST.tsv", gdir);
    FILE *m = fopen(path, "r");
    CHECK(m != NULL, "manifest %s readable", path);
    if (!m) return 1;
    char members[64][128];
    unsigned nmembers = 0, rows = 0, pe_rows = 0, nxo_rows = 0;
    uint8_t *first_golden = NULL, *first_nova = NULL;
    size_t first_gn = 0, first_nn = 0;
    char first_sha[65] = "";
    while (fgets(line, sizeof line, m)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char member[128], src[512], kind[8], golden[512], want[80];
        if (sscanf(line, "%127[^\t]\t%511[^\t]\t%7[^\t]\t%511[^\t]\t%79s", member, src, kind, golden, want) != 5) {
            CHECK(0, "manifest line not understood: %s", line);
            continue;
        }
        rows++;
        cases++;
        if (!strcmp(kind, "pe")) pe_rows++; else if (!strcmp(kind, "nxo")) nxo_rows++;
        CHECK(!strcmp(kind, "pe") || !strcmp(kind, "nxo"), "%s: kind %s is pe or nxo", member, kind);
        unsigned k;
        for (k = 0; k < nmembers && strcmp(members[k], member); k++) {}
        if (k == nmembers && nmembers < 64) snprintf(members[nmembers++], 128, "%s", member);
        snprintf(path, sizeof path, "%s/%s", gdir, golden);
        size_t gn = 0, cn = 0, nn = 0;
        uint8_t *g = loadf(path, &gn), *cbytes = NULL, *nbytes = NULL;
        CHECK(g != NULL, "%s %s: golden %s exists", member, kind, path);
        if (!g) continue;
        char got[65];
        sha256_hex(g, gn, got);
        CHECK(!strcmp(got, want), "%s %s: golden sha256 %s, manifest says %s", member, kind, got, want);
        int cok = c_reference(src, kind, &cbytes, &cn);
        CHECK(cok, "%s %s: C reference compiles %s", member, kind, src);
        CHECK(cok && same(cbytes, cn, g, gn), "%s %s: C reference, rebuilt now, still writes the golden (%zu vs %zu bytes)",
              member, kind, cn, gn);
        uint64_t code = 0;
        int nok = nova_writer(&img, src, kind, &nbytes, &nn, &code);
        CHECK(nok, "%s %s: Nova writer answers 0 (got %" PRIu64 ")", member, kind, code);
        int nsame = nok && same(nbytes, nn, g, gn);
        size_t first_diff = 0;
        if (nok && !nsame) while (first_diff < nn && first_diff < gn && nbytes[first_diff] == g[first_diff]) first_diff++;
        CHECK(nsame, "%s %s: Nova writer bytes equal the golden (%zu vs %zu bytes, first difference at 0x%zx)", member,
              kind, nn, gn, first_diff);
        printf("GOLDEN %s %s bytes=%zu sha256=%.16s c_rebuilt=%s nova=%s\n", member, kind, gn, got,
               cok && same(cbytes, cn, g, gn) ? "equal" : "DIFFERENT", nsame ? "equal" : nok ? "DIFFERENT" : "REFUSED");
        if (!first_golden && nsame) {
            first_golden = g; first_gn = gn; first_nova = nbytes; first_nn = nn; memcpy(first_sha, got, 65);
            g = NULL; nbytes = NULL;
        }
        free(g); free(cbytes); free(nbytes);
    }
    fclose(m);
    /* clôture de population : chaque source du corpus mono-fichier a ses deux lignes */
    DIR *d = opendir(srcdir);
    unsigned sources = 0;
    CHECK(d != NULL, "source directory %s readable", srcdir);
    for (struct dirent *e; d && (e = readdir(d));) {
        size_t l = strlen(e->d_name);
        if (l < 7 || strcmp(e->d_name + l - 6, ".ntasm")) continue;
        sources++;
        char name[256];
        snprintf(name, sizeof name, "%.*s", (int)(l - 6), e->d_name);
        unsigned k;
        for (k = 0; k < nmembers && strcmp(members[k], name); k++) {}
        CHECK(k < nmembers, "population: source %s/%s has no golden row", srcdir, e->d_name);
    }
    if (d) closedir(d);
    CHECK(nmembers == sources && pe_rows == sources && nxo_rows == sources,
          "population closed both ways: %u sources, %u members, %u pe rows, %u nxo rows", sources, nmembers, pe_rows,
          nxo_rows);
    /* contrôles négatifs : la comparaison et l'empreinte voient un octet basculé */
    CHECK(first_golden != NULL, "a matching row exists for the negative controls");
    if (first_golden) {
        unsigned seen = 0;
        size_t sites[3] = {0, first_gn / 2, first_gn - 1};
        for (int i = 0; i < 3; i++) {
            first_golden[sites[i]] ^= 0x01;
            char s[65];
            sha256_hex(first_golden, first_gn, s);
            int cmp_sees = !same(first_nova, first_nn, first_golden, first_gn), sha_sees = strcmp(s, first_sha) != 0;
            CHECK(cmp_sees && sha_sees, "PROOF_INVALID: a flipped golden byte at 0x%zx is %s by the comparison and %s by the digest",
                  sites[i], cmp_sees ? "seen" : "NOT SEEN", sha_sees ? "seen" : "NOT SEEN");
            seen += cmp_sees && sha_sees;
            first_golden[sites[i]] ^= 0x01;
        }
        printf("GOLDEN_NEGATIVE flips=3 seen=%u\n", seen);
    }
    free(first_golden); free(first_nova);
    nova_host_unmap(&img);
    nt_artifact_free(&art);
    for (unsigned i = 0; i < NPATHS; i++) free(srcs[i]);
    printf("NTASM_NOVA_OUTPUT_GOLDENS checks=%u failures=%u cases=%u rows=%u members=%u sources=%u\n", checks, failures,
           cases, rows, nmembers, sources);
    return failures != 0;
}
