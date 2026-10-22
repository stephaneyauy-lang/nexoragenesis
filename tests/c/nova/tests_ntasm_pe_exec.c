/* BOOTSTRAP_C_TEST — A7, lot « Exécution » du coordinateur Claude (4 octobre 2026).
 * Candidat pour tests/c/nova/tests_ntasm_pe_exec.c, non intégré.
 *
 * Charge les OCTETS d'un fichier PE32+ EFI tel qu'un producteur l'a écrit sur
 * disque, sans passer par l'artefact du compilateur : sections placées selon
 * leurs en-têtes dans une image RW, relocations de base DIR64 appliquées pour
 * l'adresse réelle, puis chaque section scellée selon ses caractéristiques
 * (jamais W+X). L'entrée est appelée en ms_abi dans un processus fils, et le
 * u64 COMPLET qu'elle rend est comparé à la valeur attendue, écrite à partir
 * de la source dans le manifeste, pas lue dans une sortie.
 *
 * Usage : pe_exec MANIFESTE
 *   ligne « pos NOM CHEMIN.efi ATTENDU »    le PE doit rendre ATTENDU
 *   ligne « neg NOM CHEMIN.efi OFFSET XOR ATTENDU_POS »
 *         le même PE, l'octet de fichier OFFSET XOR la valeur XOR : il doit être
 *         REFUSÉ par le chargeur, tué par un signal, ou rendre autre chose
 *         qu'ATTENDU_POS. S'il rend encore ATTENDU_POS, la perturbation n'a rien
 *         prouvé et la porte rougit.
 *   ligne « bad NOM CHEMIN.efi OFFSET XOR » le chargeur DOIT refuser.
 * Bannière : NTASM_NOVA_PE_EXEC checks=N failures=N cases=N */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

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

static uint16_t r16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t r32(const uint8_t *p) { return (uint32_t)r16(p) | (uint32_t)r16(p + 2) << 16; }
static uint64_t r64(const uint8_t *p) { return (uint64_t)r32(p) | (uint64_t)r32(p + 4) << 32; }

typedef uint64_t (__attribute__((ms_abi)) *EfiEntry)(void *, void *);

/* Charge et appelle. Rend 0 et *result en cas de succès, sinon un motif de
 * refus non nul (écrit dans why). Ne s'exécute que dans le processus fils. */
static int load_and_call(const uint8_t *f, size_t n, uint64_t *result, char *why, size_t wn)
{
#define REFUSE(...) do { snprintf(why, wn, __VA_ARGS__); return 1; } while (0)
    if (n < 0x40 || f[0] != 'M' || f[1] != 'Z') REFUSE("no MZ header");
    uint32_t pe = r32(f + 0x3c);
    if (pe > n - 24 || memcmp(f + pe, "PE\0\0", 4)) REFUSE("no PE signature");
    const uint8_t *coff = f + pe + 4;
    if (r16(coff) != 0x8664) REFUSE("machine is not x86-64");
    unsigned nsec = r16(coff + 2), optsz = r16(coff + 16);
    const uint8_t *opt = coff + 20;
    if ((size_t)(opt - f) + optsz > n || optsz < 112 + 6 * 8) REFUSE("optional header out of file");
    if (r16(opt) != 0x20b) REFUSE("not PE32+");
    if (r16(opt + 68) != 10) REFUSE("subsystem %u is not EFI application", r16(opt + 68));
    uint32_t entry = r32(opt + 16), size_image = r32(opt + 56), size_headers = r32(opt + 60);
    uint64_t image_base = r64(opt + 24);
    if (r32(opt + 108) < 6) REFUSE("no base relocation directory");
    uint32_t reloc_rva = r32(opt + 112 + 5 * 8), reloc_size = r32(opt + 112 + 5 * 8 + 4);
    if (!size_image || size_image > (64u << 20) || size_headers > size_image || size_headers > n)
        REFUSE("image size");
    const uint8_t *sec = opt + optsz;
    if ((size_t)(sec - f) + 40 * (size_t)nsec > n) REFUSE("section table out of file");
    uint8_t *img = mmap(NULL, size_image, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (img == MAP_FAILED) REFUSE("mmap %s", strerror(errno));
    memcpy(img, f, size_headers);
    int text_seen = 0;
    for (unsigned i = 0; i < nsec; i++) {
        const uint8_t *s = sec + 40 * i;
        uint32_t vs = r32(s + 8), va = r32(s + 12), rs = r32(s + 16), rp = r32(s + 20), ch = r32(s + 36);
        uint32_t copy = rs < vs ? rs : vs;
        if (va < size_headers || va > size_image || vs > size_image - va) REFUSE("section %u outside image", i);
        if (copy && (rp > n || copy > n - rp)) REFUSE("section %u raw data outside file", i);
        if ((ch & 0x20000000u) && (ch & 0x80000000u)) REFUSE("section %u is W+X", i);
        memcpy(img + va, f + rp, copy);
        if (ch & 0x20000000u && entry >= va && entry < va + vs) text_seen = 1;
    }
    if (!text_seen) REFUSE("entry 0x%" PRIx32 " is not in an executable section", entry);
    /* Relocations de base : l'image n'est pas à image_base, donc chaque DIR64
     * doit être corrigé de delta, sinon un pointeur absolu vise l'adresse de
     * liaison, qui n'est pas mappée. */
    uint64_t delta = (uint64_t)(uintptr_t)img - image_base;
    uint32_t at = 0;
    if (reloc_size && (reloc_rva > size_image || reloc_size > size_image - reloc_rva)) REFUSE("reloc dir outside image");
    while (at + 8 <= reloc_size) {
        uint32_t page = r32(img + reloc_rva + at), block = r32(img + reloc_rva + at + 4);
        if (block < 8 || block > reloc_size - at) REFUSE("reloc block size %" PRIu32, block);
        for (uint32_t e = 8; e + 2 <= block; e += 2) {
            uint16_t v = r16(img + reloc_rva + at + e);
            unsigned type = v >> 12, off = v & 0xfff;
            if (type == 0) continue;
            if (type != 10) REFUSE("reloc type %u", type);
            if (page > size_image - 8 || off > size_image - 8 - page) REFUSE("reloc site outside image");
            uint64_t old = r64(img + page + off), now = old + delta;
            /* Une application EFI de ce corpus n'importe rien : tout pointeur
             * absolu relocalisé vise SA propre image. Un chargeur qui oublierait
             * delta échouerait ici sur chaque cas positif. */
            if (now < (uint64_t)(uintptr_t)img || now >= (uint64_t)(uintptr_t)img + size_image)
                REFUSE("DIR64 at rva 0x%" PRIx32 " points outside the image after relocation", page + off);
            memcpy(img + page + off, &now, 8);
        }
        at += block;
    }
    for (unsigned i = 0; i < nsec; i++) {
        const uint8_t *s = sec + 40 * i;
        uint32_t vs = r32(s + 8), va = r32(s + 12), ch = r32(s + 36);
        uintptr_t lo = (uintptr_t)(img + va) & ~(uintptr_t)4095, hi = (uintptr_t)(img + va + vs);
        int prot = PROT_READ | (ch & 0x80000000u ? PROT_WRITE : 0) | (ch & 0x20000000u ? PROT_EXEC : 0);
        if (vs && mprotect((void *)lo, hi - lo, prot)) REFUSE("mprotect section %u: %s", i, strerror(errno));
    }
    *result = ((EfiEntry)(void *)(img + entry))((void *)0x1, NULL);
    return 0;
#undef REFUSE
}

/* 0 : exécuté, *value rempli ; 1 : refusé par le chargeur ; 2 : tué par un signal. */
static int run_child(const uint8_t *f, size_t n, uint64_t *value, char *why, size_t wn)
{
    int fd[2];
    if (pipe(fd)) { snprintf(why, wn, "pipe"); return 1; }
    pid_t pid = fork();
    if (pid == 0) {
        uint64_t r = 0;
        char w[200] = {0};
        close(fd[0]);
        int rc = load_and_call(f, n, &r, w, sizeof w);
        uint8_t tag = (uint8_t)rc;
        if (write(fd[1], &tag, 1) != 1 || write(fd[1], &r, 8) != 8 || write(fd[1], w, sizeof w) != (ssize_t)sizeof w) _exit(3);
        _exit(0);
    }
    close(fd[1]);
    uint8_t tag = 9;
    char w[200] = {0};
    ssize_t got = read(fd[0], &tag, 1);
    got += read(fd[0], value, 8);
    got += read(fd[0], w, sizeof w);
    close(fd[0]);
    int st = 0;
    waitpid(pid, &st, 0);
    if (WIFSIGNALED(st)) { snprintf(why, wn, "killed by signal %d", WTERMSIG(st)); return 2; }
    if (got != 1 + 8 + (ssize_t)sizeof w) {
        /* Sous ASan, un SIGSEGV du fils est intercepté et devient une sortie
         * non nulle : c'est un plantage, pas un refus du chargeur. */
        snprintf(why, wn, "child died before reporting (exit status %d)", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
        return 2;
    }
    snprintf(why, wn, "%s", w);
    return tag ? 1 : 0;
}

static uint8_t *readall(const char *p, size_t *n)
{
    FILE *fp = fopen(p, "rb");
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END);
    long l = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    uint8_t *b = malloc(l > 0 ? (size_t)l : 1);
    if (!b || fread(b, 1, (size_t)l, fp) != (size_t)l) { fclose(fp); free(b); return NULL; }
    fclose(fp);
    *n = (size_t)l;
    return b;
}

int main(int argc, char **argv)
{
    /* Sans argument, comme ngbuild.sh la lance : le manifeste des goldens, dont les PE sont ceux de la référence C
     * que la porte output_goldens égale octet pour octet à la sortie du writer Nova. */
    const char *mpath = argc == 2 ? argv[1] : "out/c-bootstrap/nova/goldens/pe-exec.manifest";
    if (argc > 2) { fprintf(stderr, "usage: pe_exec [MANIFEST]\n"); return 2; }
    FILE *m = fopen(mpath, "r");
    if (!m) {
        fprintf(stderr, "FAIL cannot open manifest %s\n", mpath);
        printf("NTASM_NOVA_PE_EXEC checks=1 failures=1 cases=0\n");
        return 1;
    }
    char line[1024];
    unsigned pos = 0, neg = 0, bad = 0;
    while (fgets(line, sizeof line, m)) {
        char kind[8], name[128], path[700], na[40] = "", nb[40] = "", nc[40] = "";
        uint64_t a = 0, b = 0, c = 0;
        if (line[0] == '#' || line[0] == '\n') continue;
        /* Les nombres sont lus par strtoull : un scanf signé (SCNi64) sature
         * 0xffffffffffffffff en 0x7fffffffffffffff, une valeur que le manifeste
         * ne contient pas -- mesuré sur ce fichier même, le 4 octobre 2026. */
        int k = sscanf(line, "%7s %127s %699s %39s %39s %39s", kind, name, path, na, nb, nc);
        a = strtoull(na, NULL, 0);
        b = strtoull(nb, NULL, 0);
        c = strtoull(nc, NULL, 0);
        size_t n = 0;
        uint8_t *f = k >= 3 ? readall(path, &n) : NULL;
        CHECK(f != NULL, "%s: PE file %s readable", name, k >= 3 ? path : "?");
        if (!f) continue;
        uint64_t v = 0;
        char why[256] = {0};
        cases++;
        if (!strcmp(kind, "pos") && k == 4) {
            int rc = run_child(f, n, &v, why, sizeof why);
            CHECK(rc == 0, "%s: loaded and executed (%s)", name, why);
            CHECK(rc == 0 && v == a, "%s: returned 0x%" PRIx64 ", want 0x%" PRIx64, name, v, a);
            printf("PE_EXEC pos %s want=0x%" PRIx64 " got=%s0x%" PRIx64 "%s\n", name, a, rc ? "<" : "", v,
                   rc ? ">" : "");
            pos++;
        } else if (!strcmp(kind, "neg") && k == 6) {
            CHECK(a < n, "%s: perturbation offset inside the file", name);
            if (a < n) f[a] ^= (uint8_t)b;
            int rc = run_child(f, n, &v, why, sizeof why);
            CHECK(!(rc == 0 && v == c),
                  "%s: offset 0x%" PRIx64 " xor 0x%" PRIx64 " STILL returns 0x%" PRIx64 " -- PROOF_INVALID, the perturbation proves nothing",
                  name, a, b, c);
            printf("PE_EXEC neg %s offset=0x%" PRIx64 " xor=0x%" PRIx64 " outcome=%s value=0x%" PRIx64 " (%s)\n", name, a,
                   b, rc == 0 ? "returned" : rc == 1 ? "refused" : "crash", v, why);
            neg++;
        } else if (!strcmp(kind, "bad") && k == 5) {
            CHECK(a < n, "%s: perturbation offset inside the file", name);
            if (a < n) f[a] ^= (uint8_t)b;
            int rc = run_child(f, n, &v, why, sizeof why);
            CHECK(rc == 1, "%s: loader must refuse, outcome %d (%s)", name, rc, why);
            printf("PE_EXEC bad %s offset=0x%" PRIx64 " refused=%s (%s)\n", name, a, rc == 1 ? "yes" : "NO", why);
            bad++;
        } else {
            CHECK(0, "manifest line not understood: %s", line);
        }
        free(f);
    }
    fclose(m);
    CHECK(pos > 0 && neg > 0 && bad > 0, "manifest exercises all three kinds (pos=%u neg=%u bad=%u)", pos, neg, bad);
    printf("NTASM_NOVA_PE_EXEC checks=%u failures=%u cases=%u pos=%u neg=%u bad=%u\n", checks, failures, cases, pos,
           neg, bad);
    return failures != 0;
}
