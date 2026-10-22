#define _GNU_SOURCE
/* C_SEED_ORACLE for the MANY PILOT ONLY.
 *
 * C builds the NVSRC001 bundles as raw bytes (header, span table, blob), calls
 * the pilot's ABI2 entry once per case with a real NovaContextV2, and then
 * reads ONLY the produced OUTPUT.EFI: every source inside NOVA.IN is parsed,
 * resolved, lowered and emitted by the EXECUTING Nova pilot, never by this file.
 * The produced PE is an ABI2 image: it is validated, relocated and sealed by
 * the loader below (the verified PE checks, unchanged) and entered in a
 * bounded child as ms_abi (NovaContextV2 *, const u64 *, u64) with a REAL
 * context and args=NULL/count=0. The u64 and the context error that come back
 * are therefore the executed bytes' own, not an EFI-handle-shaped guess.
 *
 * The seed image is compiled through the existing opt-in closed-application
 * reachability API: the pilot's closure is large, and the host mapper enforces
 * rdata<=16MiB, data<=16MiB, text<=32MiB. Nothing here is published as an
 * A8 self-hosting proof. */
#include <unistd.h>
#include <signal.h>
static pid_t driver_observer_fork(void) { pid_t p=fork(); if(p==0)alarm(5); return p; }
#define fork driver_observer_fork
#define main independent_pe_observer_reference_main
#include "tests_ntasm_pe_exec.c"
#undef main
#undef fork
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include <sys/stat.h>

/* THE APPLICATION ENTRY COMES FIRST, and it declares no function: the pilot's
 * own `export fn main()->u64` is the program's ONLY main, so an entry that
 * declared one would make public_entry_v2 refuse the whole closure. Placed
 * first, the entry is source 1, so its `import nova_native_driver_many` is
 * resolved against the other inputs (nova.c module_headers refuses an imported
 * module that is not an input). The remaining 56 rows are the pilot and its
 * real dependencies; the count is DRIVER_CLOSURE_N, never a literal. The last
 * three rows are the ones the LOT path added: the batch orchestrator, the
 * linker over a list and the merger it calls. They are named ONCE each, and
 * they are here because the pilot imports them. */
static const char *const DRIVER_CLOSURE[] = {
    "tests/nova/tests/nova-native-driver-many-entry.nova",
    "compiler/nova/drivers/nova_native_driver_many.nova",
    "compiler/nova/ir/machine_pipeline.nova",
    "compiler/nova/frontend/stub_table.nova",
    "compiler/nova/analysis/validate.nova",
    "compiler/nova/macros/macro_splice.nova",
    "compiler/nova/formats/ntir/ntir.nova",
    "compiler/nova/macros/macro_expand.nova",
    "compiler/nova/analysis/types/constant_types.nova",
    "compiler/nova/macros/constant_eval.nova",
    "compiler/nova/analysis/types/initializer_types.nova",
    "compiler/nova/analysis/types/condition_types.nova",
    "compiler/nova/analysis/types/literal_initializers.nova",
    "compiler/nova/frontend/targets.nova",
    "compiler/nova/frontend/versions.nova",
    "compiler/nova/analysis/abi/feature_requirements.nova",
    "compiler/nova/analysis/abi/features.nova",
    "compiler/nova/analysis/types/pointer_spaces.nova",
    "compiler/nova/analysis/control_flow.nova",
    "compiler/nova/analysis/types/return_types.nova",
    "compiler/nova/analysis/abi/body_clobbers.nova",
    "compiler/nova/analysis/abi/body_intrinsics.nova",
    "compiler/nova/analysis/abi/body_effects.nova",
    "compiler/nova/analysis/calls/call_contracts.nova",
    "compiler/nova/analysis/abi/abi.nova",
    "compiler/nova/analysis/calls/call_clobbers.nova",
    "compiler/nova/analysis/calls/call_effects.nova",
    "compiler/nova/analysis/calls/call_types.nova",
    "compiler/nova/analysis/calls/calls.nova",
    "compiler/nova/frontend/refs.nova",
    "compiler/nova/analysis/abi/clobbers.nova",
    "compiler/nova/analysis/abi/contracts.nova",
    "compiler/nova/analysis/abi/effects.nova",
    "compiler/nova/analysis/types/register_widths.nova",
    "compiler/nova/frontend/register_bindings.nova",
    "compiler/nova/frontend/bindings.nova",
    "compiler/nova/frontend/locals.nova",
    "compiler/nova/frontend/parameters.nova",
    "compiler/nova/analysis/types/types.nova",
    "compiler/nova/frontend/symbol_names.nova",
    "compiler/nova/analysis/calls/callable_names.nova",
    "compiler/nova/analysis/semantics.nova",
    "compiler/nova/frontend/parser.nova",
    "compiler/nova/frontend/ast.nova",
    "compiler/nova/frontend/lexer.nova",
    "compiler/nova/ir/machine_ir.nova",
    "compiler/nova/backend/nova/machine_emit.nova",
    "compiler/nova/backend/x64/x64_fixed.nova",
    "compiler/nova/formats/nxo/nxo.nova",
    "compiler/nova/formats/nxo/nxo_pe.nova",
    "compiler/nova/formats/pe/pe.nova",
    "compiler/nova/frontend/nova_language_parse.nova",
    "compiler/nova/backend/nova/nova_machine_many.nova",
    "compiler/nova/backend/nova/nova_machine_lower.nova",
    "compiler/nova/backend/nova/nova_machine_batches.nova",
    "compiler/nova/formats/nxo/nxo_link_pe.nova",
    "compiler/nova/formats/nxo/nxo_merge.nova",
};
#define DRIVER_CLOSURE_N (sizeof DRIVER_CLOSURE / sizeof DRIVER_CLOSURE[0])

/* The compiler refuses an import that is not among its inputs, and refuses two
 * mains. So "the entry is compiled and imports the pilot, with no second main"
 * is proven by the compile succeeding with BOTH rows present exactly once. */
static int closure_count(const char *name) {
    int n = 0;
    for (size_t i = 0; i < DRIVER_CLOSURE_N; i++)
        if (!strcmp(DRIVER_CLOSURE[i], name)) n++;
    return n;
}
static uint8_t *bounded_read(const char *path, size_t max, size_t *size) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    uint8_t *bytes = NULL;
    long n;
    if (fseek(f, 0, SEEK_END) || (n = ftell(f)) < 0 || (uint64_t)n > max || fseek(f, 0, SEEK_SET))
        goto done;
    bytes = malloc((size_t)n + 1);
    if (!bytes) goto done;
    if (fread(bytes, 1, (size_t)n, f) != (size_t)n || ferror(f)) { free(bytes); bytes = NULL; goto done; }
    bytes[n] = 0;
    *size = (size_t)n;
done:
    if (fclose(f)) { free(bytes); bytes = NULL; }
    return bytes;
}
static int joined(char *out, size_t n, const char *dir, const char *name) {
    int k = snprintf(out, n, "%s/%s", dir, name);
    return k > 0 && (size_t)k < n;
}
static int fresh_write(const char *path, const void *data, size_t n) {
    FILE *f = fopen(path, "wbx");
    if (!f) return 0;
    int ok = fwrite(data, 1, n, f) == n && !ferror(f);
    if (fclose(f)) ok = 0;
    return ok;
}
/* OUTPUT.EFI IS AN ABI2 IMAGE. Its entry is entered as
 * ms_abi (NovaContextV2 *, const u64 *args, u64 count): a fixture that
 * allocates or measures a buffer reaches the runtime THROUGH THAT POINTER, so
 * a caller that passed the EFI handle pair would crash on every such fixture
 * instead of reading the value the bytes return. The call below uses a context
 * that is really initialized, args=NULL and count=0.
 *
 * The validation, relocation and sealing are the verified loader's, unchanged
 * in what they refuse: MZ/PE, x86-64, PE32+, EFI subsystem 10, relocation
 * directory present, sections inside file and image, no W+X section, entry in
 * an executable section, DIR64 only, every relocated pointer inside the image,
 * and pages aligned by ~4095 (never ~4096). Nothing is ever mapped RWX: each
 * section is sealed read-only, read+write, or read+execute from its own
 * characteristics, and the header pages keep the mapper's read+write. */
typedef uint64_t(NOVA_ABI *ManyAbi2Entry)(NovaContextV2 *, const uint64_t *, uint64_t);
static int many_pe_execute(const uint8_t *f, size_t n, uint64_t *result, uint64_t *error,
                           char *why, size_t wn) {
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
    uint64_t delta = (uint64_t)(uintptr_t)img - image_base;
    uint32_t at = 0;
    if (reloc_size && (reloc_rva > size_image || reloc_size > size_image - reloc_rva))
        REFUSE("reloc dir outside image");
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
    NovaContextV2 context = {0};
    if (!nova_context_init_v2(&context)) REFUSE("runtime context init");
    ManyAbi2Entry main_entry = (ManyAbi2Entry)(void *)(img + entry);
    *result = main_entry(&context, NULL, 0);
    /* BOTH answers are captured BEFORE the destroy: after it the context is
     * gone, and a reader of a destroyed context would be reading this oracle's
     * own stack instead of the call's error. */
    *error = context.error;
    int destroyed = nova_context_destroy_v2(&context);
    if (!destroyed) REFUSE("runtime context destroy");
    return 0;
#undef REFUSE
}

/* 0 = entered, value and error outputs filled; 1 = refused by loader or context;
 * 2 = killed by a signal (the child is bounded by alarm(5)). */
static int many_pe_observe(const uint8_t *f, size_t n, uint64_t *value, uint64_t *error,
                           char *why, size_t wn) {
    int fd[2];
    if (pipe(fd)) { snprintf(why, wn, "pipe"); return 1; }
    pid_t pid = driver_observer_fork();
    if (pid == 0) {
        uint64_t r = 0, e = 0;
        char w[200] = {0};
        close(fd[0]);
        int rc = many_pe_execute(f, n, &r, &e, w, sizeof w);
        uint8_t tag = (uint8_t)rc;
        if (write(fd[1], &tag, 1) != 1 || write(fd[1], &r, 8) != 8 ||
            write(fd[1], &e, 8) != 8 || write(fd[1], w, sizeof w) != (ssize_t)sizeof w)
            _exit(3);
        _exit(0);
    }
    close(fd[1]);
    uint8_t tag = 9;
    char w[200] = {0};
    ssize_t got = read(fd[0], &tag, 1);
    got += read(fd[0], value, 8);
    got += read(fd[0], error, 8);
    got += read(fd[0], w, sizeof w);
    close(fd[0]);
    /* The child's reason buffer is NUL-terminated by snprintf, but the pipe
     * read can fill the whole array: the last byte is forced so the %s below
     * cannot run past what the child actually wrote. */
    w[sizeof w - 1] = 0;
    int st = 0;
    waitpid(pid, &st, 0);
    if (WIFSIGNALED(st)) { snprintf(why, wn, "killed by signal %d", WTERMSIG(st)); return 2; }
    if (got != 1 + 8 + 8 + (ssize_t)sizeof w) {
        snprintf(why, wn, "child died before reporting (exit status %d)",
                 WIFEXITED(st) ? WEXITSTATUS(st) : -1);
        return 2;
    }
    snprintf(why, wn, "%s", w);
    return tag ? 1 : 0;
}

/* The independent observer: the bytes on disk, entered as ABI2 in a child. */
static int observe(const char *path, uint64_t expected) {
    size_t n = 0;
    uint8_t *bytes = bounded_read(path, 16u * 1024u * 1024u, &n);
    CHECK(bytes && n, "independent observer reads the actual PE file");
    if (!bytes || !n) { free(bytes); return 0; }
    uint64_t got = 0, error = UINT64_MAX;
    char why[256] = {0};
    int rc = many_pe_observe(bytes, n, &got, &error, why, sizeof why);
    CHECK(rc == 0 && got == expected && error == 0,
          "ABI2 observer rc=%d got=%" PRIu64 " error=%" PRIu64 " expected=%" PRIu64 " %s",
          rc, got, error, expected, why);
    printf("NOVA_DRIVER_MANY_PE_OBSERVER file=%s bytes=%zu rc=%d returned=%" PRIu64
           " runtime_error=%" PRIu64 " expected=%" PRIu64
           " call=abi2(ctx,args=NULL,count=0) source_not_compiled_by_C=yes\n",
           path, n, rc, got, error, expected);
    free(bytes);
    return rc == 0 && got == expected && error == 0;
}

/* ---- the bundles: raw bytes, built here, never parsed here --------------- */
static void put64(uint8_t *p, uint64_t v) {
    for (unsigned i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}
typedef struct { uint8_t *bytes; size_t size; } Bundle;
static Bundle bundle_make(const char *const *sources, size_t count, uint64_t root) {
    Bundle b = {NULL, 0};
    size_t lens[64], blob = 0;
    if (count < 1 || count > 64) return b;
    for (size_t i = 0; i < count; i++) {
        lens[i] = strlen(sources[i]);
        if (lens[i] == 0 || lens[i] > 65535) return b;
        blob += lens[i];
    }
    if (blob > 4u * 1024u * 1024u) return b;
    size_t total = 32 + 16 * count + blob;
    uint8_t *p = malloc(total);
    if (!p) return b;
    memcpy(p, "NVSRC001", 8);
    put64(p + 8, count);
    put64(p + 16, root);
    put64(p + 24, blob);
    size_t at = 0;
    for (size_t i = 0; i < count; i++) {
        put64(p + 32 + 16 * i, at);
        put64(p + 40 + 16 * i, lens[i]);
        at += lens[i];
    }
    at = 0;
    for (size_t i = 0; i < count; i++) {
        memcpy(p + 32 + 16 * count + at, sources[i], lens[i]);
        at += lens[i];
    }
    b.bytes = p;
    b.size = total;
    return b;
}

static const char *const TWO42[] = {
    "module app;\nimport lib;\nexport fn main() -> u64 { return lib.answer(); }\n",
    "module lib;\nexport fn answer() -> u64 { return 42; }\n",
};
static const char *const TWO43[] = {
    "module app;\nimport lib;\nexport fn main() -> u64 { return lib.answer(); }\n",
    "module lib;\nexport fn answer() -> u64 { return 43; }\n",
};
/* record + buffer + string: Item{36}, alloc(runtime(),2), "abcd" -> 36+2+4. */
static const char *const RECORD[] = {
    "module app;\nimport lib;\nexport fn main() -> u64 { let b: buf<u8> = alloc(runtime(), 2); "
    "let s: buf<u8> = \"abcd\"; return lib.total(b) + len(s); }\n",
    "module lib;\nexport struct Item { value: u64 }\nexport fn make() -> Item { return Item{value: 36}; }"
    "\nexport fn total(b: buf<u8>) -> u64 { let p: Item = make(); return p.value + len(b); }\n",
};

enum {
    M_TWO42, M_TWO43, M_RECORD, M_HEADER_TRUNCATED, M_FAKE_MAGIC, M_COUNT_ZERO,
    M_BAD_ROOT, M_BAD_SPAN, M_SUFFIX, M_EXISTING_OUTPUT, M_MISSING_NOVA_IN
};
typedef struct {
    const char *name;
    int kind;
    uint64_t code;  /* the pilot's own return */
    uint64_t error; /* context.error after the call */
    uint64_t pe;    /* the produced PE's own returned u64 */
} ManyCase;
/* The expected 110x values are the pilot's published getters
 * (nova_native_driver_many.nova); the observer prints the value it really got,
 * so a drifted number appears in the log instead of matching a stale copy. */
static const ManyCase many_cases[] = {
    {"two-modules-42", M_TWO42, 0, 0, 42},
    {"two-modules-43", M_TWO43, 0, 0, 43},
    {"record-buffer-string", M_RECORD, 0, 0, 42},
    {"header-truncated", M_HEADER_TRUNCATED, 1101, 0, 0},
    {"fake-magic", M_FAKE_MAGIC, 1102, 0, 0},
    {"count-zero", M_COUNT_ZERO, 1104, 0, 0},
    {"invalid-root", M_BAD_ROOT, 1105, 0, 0},
    {"invalid-span", M_BAD_SPAN, 1106, 0, 0},
    {"suffix-byte", M_SUFFIX, 1103, 0, 0},
    /* rt_open_new opens "wbx": the existing file is refused by the runtime, so
     * the entry returns 0 with NV2_IO and the bytes are untouched. */
    {"output-existing", M_EXISTING_OUTPUT, 0, NV2_IO, 0},
    {"nova-in-missing", M_MISSING_NOVA_IN, 0, NV2_IO, 0},
};

static void many_case(const ManyCase *t, NovaHostImage *image, const char *proof_root) {
    char dir[4096], input[4096], output[4096], meta[4096], cwd[4096];
    CHECK(joined(dir, sizeof dir, proof_root, t->name), "case directory path fits");
    CHECK(joined(input, sizeof input, dir, "NOVA.IN"), "input path fits");
    CHECK(joined(output, sizeof output, dir, "OUTPUT.EFI"), "output path fits");
    CHECK(joined(meta, sizeof meta, dir, "oracle.json"), "oracle metadata path fits");
    if (failures) return;
    CHECK(mkdir(dir, 0777) == 0, "case directory must be fresh");
    if (failures) return;
    Bundle b = {NULL, 0};
    size_t file_size = 0;
    if (t->kind == M_TWO42) b = bundle_make(TWO42, 2, 0);
    else if (t->kind == M_TWO43) b = bundle_make(TWO43, 2, 0);
    else if (t->kind == M_RECORD) b = bundle_make(RECORD, 2, 0);
    else if (t->kind != M_MISSING_NOVA_IN) b = bundle_make(TWO42, 2, 0);
    if (t->kind != M_MISSING_NOVA_IN) CHECK(b.bytes && b.size >= 32, "%s: bundle built from source bytes", t->name);
    if (failures || (t->kind != M_MISSING_NOVA_IN && !b.bytes)) { free(b.bytes); return; }
    file_size = b.size;
    if (t->kind == M_HEADER_TRUNCATED) file_size = 16;
    if (t->kind == M_FAKE_MAGIC) b.bytes[3] = 'X';
    if (t->kind == M_COUNT_ZERO) put64(b.bytes + 8, 0);
    if (t->kind == M_BAD_ROOT) put64(b.bytes + 16, 2); /* count is 2: root==count */
    if (t->kind == M_BAD_SPAN) put64(b.bytes + 40, (uint64_t)(b.size - 32 - 16 * 2) + 1);
    if (t->kind == M_SUFFIX) {
        uint8_t *grown = realloc(b.bytes, b.size + 1);
        CHECK(grown != NULL, "suffix fixture grows the bundle by one byte");
        if (grown) { grown[b.size] = 0; b.bytes = grown; file_size = b.size + 1; }
    }
    if (t->kind == M_EXISTING_OUTPUT) CHECK(fresh_write(output, "UNCHANGED", 9), "preexisting output control");
    if (t->kind != M_MISSING_NOVA_IN) CHECK(fresh_write(input, b.bytes, file_size), "persist NOVA.IN bytes");
    free(b.bytes);
    if (failures) return;
    CHECK(getcwd(cwd, sizeof cwd) != NULL, "save oracle cwd");
    CHECK(chdir(dir) == 0, "oracle works in the pilot's fixed input/output directory");
    if (failures) return;
    NovaContextV2 context = {0};
    int live = nova_context_init_v2(&context);
    CHECK(live, "initialize C runtime oracle");
    uint64_t got = UINT64_MAX, error = UINT64_MAX;
    if (live) {
        got = image->entry(&context, NULL, 0);
        error = context.error;
        CHECK(got == t->code && error == t->error,
              "%s pilot return=%" PRIu64 "/error=%" PRIu64 " expected=%" PRIu64 "/%" PRIu64,
              t->name, got, error, t->code, t->error);
        CHECK(nova_context_destroy_v2(&context), "oracle destroy after normal/runtime refusal");
    }
    CHECK(chdir(cwd) == 0, "restore oracle cwd");
    if (failures) return;
    if (t->kind == M_EXISTING_OUTPUT) {
        size_t keep_n = 0;
        uint8_t *keep = bounded_read(output, 64, &keep_n);
        CHECK(keep && keep_n == 9 && !memcmp(keep, "UNCHANGED", 9),
              "existing OUTPUT.EFI preserved byte for byte");
        free(keep);
    } else if (t->code == 0 && t->error == 0) {
        observe(output, t->pe);
    } else {
        errno = 0;
        int exists = access(output, F_OK);
        CHECK(exists == -1 && errno == ENOENT, "refused bundle publishes no output PE");
    }
    char json[768];
    int written = snprintf(json, sizeof json,
        "{\n \"label\":\"C_SEED_ORACLE\",\n \"case\":\"%s\",\n"
        " \"pilot_returned\":%" PRIu64 ",\n \"runtime_error_before_destroy\":%" PRIu64 ",\n"
        " \"nova_in_compiled_by_C\":false,\n \"produced_pe_expected_return\":%" PRIu64 ",\n"
        " \"A8_selfhost_proven\":false\n}\n", t->name, got, error, t->pe);
    CHECK(written > 0 && (size_t)written < sizeof json, "oracle metadata bounded");
    if (written > 0 && (size_t)written < sizeof json)
        CHECK(fresh_write(meta, json, (size_t)written), "persist exact oracle result");
    ++cases;
    printf("NOVA_NATIVE_DRIVER_MANY_ORACLE case=%s returned=%" PRIu64 " runtime=%" PRIu64
           " input_compiled_by_C=no\n", t->name, got, error);
}

int main(int argc, char **argv) {
    if (argc < 3 || argc > 4) {
        fprintf(stderr, "usage: seed absolute-candidate-root fresh-absolute-proof-root "
                        "[--closed-application]\n");
        return 2;
    }
    /* The policy is not selectable: this seed exists to compile the pilot's
     * closure under the closed-application roots, and --closed-application is
     * accepted only so a caller that spells it out is not silently ignored. */
    if (argc == 4 && strcmp(argv[3], "--closed-application")) {
        fprintf(stderr, "unknown seed argument\n");
        return 2;
    }
    CHECK(argv[1][0] == '/' && argv[2][0] == '/', "absolute POSIX candidate/output roots required");
    if (failures) return 1;
    CHECK(mkdir(argv[2], 0777) == 0, "proof root must be fresh");
    if (failures) return 1;
    char closure_dir[4096], driver_pe[4096], metadata[4096];
    CHECK(joined(closure_dir, sizeof closure_dir, argv[2], "closure"), "closure snapshot path fits");
    CHECK(joined(driver_pe, sizeof driver_pe, argv[2], "DRIVER-MANY.EFI"), "pilot PE path fits");
    CHECK(joined(metadata, sizeof metadata, argv[2], "driver-many.json"), "pilot provenance path fits");
    CHECK(mkdir(closure_dir, 0777) == 0, "closure snapshot directory fresh");
    if (failures) return 1;
    CHECK(closure_count("compiler/nova/drivers/nova_native_driver_many.nova") == 1,
          "the pilot is an input exactly once");
    CHECK(closure_count("tests/nova/tests/nova-native-driver-many-entry.nova") == 1,
          "the entry that imports the pilot is an input exactly once");
    CHECK(closure_count("compiler/nova/backend/nova/nova_machine_batches.nova") == 1,
          "the batch orchestrator is an input exactly once");
    CHECK(closure_count("compiler/nova/formats/nxo/nxo_link_pe.nova") == 1,
          "the linker over a list is an input exactly once");
    CHECK(closure_count("compiler/nova/formats/nxo/nxo_merge.nova") == 1,
          "the merger the linker calls is an input exactly once");
    if (failures) return 1;
    NtFInput inputs[DRIVER_CLOSURE_N];
    char *texts[DRIVER_CLOSURE_N];
    memset(texts, 0, sizeof texts);
    memset(inputs, 0, sizeof inputs);
    size_t total = 0;
    for (size_t i = 0; i < DRIVER_CLOSURE_N; i++) {
        char path[4096], copy[4096];
        size_t n = 0;
        CHECK(joined(path, sizeof path, argv[1], DRIVER_CLOSURE[i]), "closure input path fits");
        const char *base = strrchr(DRIVER_CLOSURE[i], '/');
        base = base ? base + 1 : DRIVER_CLOSURE[i];
        CHECK(joined(copy, sizeof copy, closure_dir, base), "closure snapshot path fits");
        if (failures) break;
        texts[i] = (char *)bounded_read(path, 1024u * 1024u, &n);
        CHECK(texts[i] != NULL, "required closure source %s", path);
        if (!texts[i]) break;
        CHECK(n <= 4u * 1024u * 1024u - total, "total seed closure bounded 4MiB");
        if (failures) break;
        total += n;
        CHECK(fresh_write(copy, texts[i], n), "persist borrowed closure source exactly");
        inputs[i] = (NtFInput){DRIVER_CLOSURE[i], texts[i], n};
    }
    NtArtifact artifact = {0};
    NovaHostImage image = {0};
    int pe_available = 0;
    NovaSeedReachabilityStats reachability = {0};
    if (!failures) {
        /* Exactly ONE selected source-to-machine-code C API call. Inputs are
         * only the DRIVER_CLOSURE_N sources above, NEVER NOVA.IN. */
        NovaSeedReachabilityOptions options = {1, sizeof options,
                                               NOVA_SEED_ENTRY_ONLY_CLOSED_APPLICATION, 0};
        int ok = nova_compile_many_v2_seed_reachable(inputs, DRIVER_CLOSURE_N, &artifact,
                                                     &options, &reachability);
        CHECK(ok && artifact.error.code == 0, "seed compiles the actual many pilot closure");
        if (!ok)
            fprintf(stderr, "DRIVER_MANY_SEED E%u source%u %zu:%zu %s\n", artifact.error.code,
                    artifact.error.source_index, artifact.error.line, artifact.error.column,
                    artifact.error.message);
    }
    if (!failures) {
        int pe_ok = nt_make_pe(&artifact);
        pe_available = pe_ok && artifact.pe.bytes && artifact.pe.size;
        fprintf(stderr, "DRIVER_MANY_SEED_PE ok=%d E%u source=%u line=%zu column=%zu message=[%s] "
                "text=%zu entry=%zu rdata=%zu data=%zu pe=%zu\n",
                pe_ok, artifact.error.code, artifact.error.source_index, artifact.error.line,
                artifact.error.column, artifact.error.message, artifact.text.size, artifact.entry,
                artifact.rdata.size, artifact.data.size, artifact.pe.size);
        CHECK(artifact.rdata.size <= 16u * 1024u * 1024u &&
              artifact.data.size <= 16u * 1024u * 1024u,
              "pilot rdata=%zu data=%zu fit the host mapper's 16MiB envelope",
              artifact.rdata.size, artifact.data.size);
        CHECK(nova_host_map(&artifact, &image), "map the actual pilot with the existing C host mapper");
        fprintf(stderr, "DRIVER_MANY_SEED modules=%zu source_bytes=%zu text_bytes=%zu "
                "pe_bytes=%zu text_host_limit=%u\n", (size_t)DRIVER_CLOSURE_N, total,
                artifact.text.size, artifact.pe.size, NOVA_HOST_TEXT_LIMIT);
        fprintf(stderr, "DRIVER_MANY_SEED_REACHABILITY policy=%u complete=%u text=%zu/%zu "
                "functions=%zu/%zu roots=%zu/%zu/%zu references=%zu relocations=%zu/%zu\n",
                reachability.root_policy, reachability.graph_complete, reachability.text_after,
                reachability.text_before, reachability.functions_kept,
                reachability.functions_before, reachability.roots_entry,
                reachability.roots_exported, reachability.roots_data,
                reachability.function_references, reachability.relocations_after,
                reachability.relocations_before);
        CHECK(reachability.graph_complete == 1, "closed-application reachability is complete");
        CHECK(reachability.text_after > 0 && reachability.text_after <= reachability.text_before,
              "closed-application text %zu does not exceed the all-exports text %zu",
              reachability.text_after, reachability.text_before);
    }
    if (!failures && image.entry) {
        for (size_t i = 0; i < sizeof many_cases / sizeof many_cases[0]; i++) {
            many_case(&many_cases[i], &image, argv[2]);
            if (failures) break;
        }
    }
    if (!failures) {
        char first[4096], second[4096];
        size_t a_n = 0, b_n = 0;
        CHECK(joined(first, sizeof first, argv[2], "two-modules-42/OUTPUT.EFI") &&
              joined(second, sizeof second, argv[2], "two-modules-43/OUTPUT.EFI"),
              "comparison output paths fit");
        uint8_t *a = bounded_read(first, 16u * 1024u * 1024u, &a_n);
        uint8_t *b = bounded_read(second, 16u * 1024u * 1024u, &b_n);
        CHECK(a && b && (a_n != b_n || memcmp(a, b, a_n) != 0),
              "changed bundle changes the emitted PE; both execute independently");
        free(a);
        free(b);
    }
    /* The number of cases is the TABLE's own size, so a row added to
     * many_cases cannot leave this line asserting an old count. */
    CHECK(cases == sizeof many_cases / sizeof many_cases[0],
          "every declared pilot case exercised: declared=%zu exercised=%u",
          sizeof many_cases / sizeof many_cases[0], cases);
    CHECK(pe_available, "UEFI seed PE unavailable; C-runtime oracles are a separate partial proof");
    if (!failures) {
        CHECK(fresh_write(driver_pe, artifact.pe.bytes, artifact.pe.size),
              "publish C_SEED pilot only after every oracle succeeded");
        char json[768];
        int n = snprintf(json, sizeof json,
            "{\n \"label\":\"C_SEED_ORACLE\",\n \"pilot_sources\":%zu,\n"
            " \"pilot_source_bytes\":%zu,\n \"pilot_text_bytes\":%zu,\n"
            " \"pilot_pe_bytes\":%zu,\n \"oracle_cases\":%zu,\n"
            " \"closed_application_reachability\":true,\n"
            " \"NOVA_IN_compiled_by_C\":false,\n \"A8_selfhost_proven\":false\n}\n",
            (size_t)DRIVER_CLOSURE_N, total, artifact.text.size, artifact.pe.size,
            sizeof many_cases / sizeof many_cases[0]);
        CHECK(n > 0 && (size_t)n < sizeof json, "pilot provenance fits");
        if (n > 0 && (size_t)n < sizeof json)
            CHECK(fresh_write(metadata, json, (size_t)n), "pilot provenance persisted");
    }
    nova_host_unmap(&image);
    nt_artifact_free(&artifact);
    for (size_t i = 0; i < DRIVER_CLOSURE_N; i++) free(texts[i]);
    printf("NTASM_NOVA_NATIVE_DRIVER_MANY_SEED checks=%u failures=%u cases=%u "
           "label=C_SEED_ORACLE NOVA_IN_compiled_by_C=no A8_selfhost_proven=no\n",
           checks, failures, cases);
    return failures ? 1 : 0;
}
