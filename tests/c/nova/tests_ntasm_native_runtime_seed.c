#define _POSIX_C_SOURCE 200809L
/* BOOTSTRAP_EXTERNAL_C seed and C-runtime oracle ONLY.
 * The generated Nova ABI2 PE is input to the native S0 runtime/host.
 * This does not compile NTASM/Nova with a native producer or prove A8.
 */
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static unsigned checks, failures, compiled, executed;
#define CHECK(condition, message) do { \
    ++checks; \
    if (!(condition)) { ++failures; fprintf(stderr, "FAIL %s\n", message); } \
} while (0)

typedef struct {
    const char *name, *source;
    uint64_t wanted_return, wanted_error;
    int roundtrip;
} Case;
static const Case cases[] = {
    {"roundtrip", "roundtrip.nova", 0, 0, 1},
    {"readonly", "readonly.nova", 0, NV2_READONLY, 0},
    {"stale", "stale.nova", 0, NV2_LIFETIME, 0}
};

static int path_join(char *out, size_t capacity, const char *dir,
                     const char *name) {
    int n = snprintf(out, capacity, "%s/%s", dir, name);
    return n > 0 && (size_t)n < capacity;
}

static unsigned char *read_source(const char *path, size_t *length) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    unsigned char *bytes = NULL;
    long size;
    if (fseek(f, 0, SEEK_END) || (size = ftell(f)) <= 0 ||
        size > 1024 * 1024 || fseek(f, 0, SEEK_SET))
        goto done;
    bytes = malloc((size_t)size + 1);
    if (!bytes) goto done;
    if (fread(bytes, 1, (size_t)size, f) != (size_t)size || ferror(f)) {
        free(bytes); bytes = NULL; goto done;
    }
    bytes[size] = 0;
    *length = (size_t)size;
done:
    if (fclose(f)) { free(bytes); bytes = NULL; }
    return bytes;
}

static int write_new(const char *path, const void *bytes, size_t count) {
    FILE *f = fopen(path, "wbx");
    if (!f) return 0;
    int ok = fwrite(bytes, 1, count, f) == count && !ferror(f);
    if (fclose(f)) ok = 0;
    return ok;
}

static int check_roundtrip_file(void) {
    static const unsigned char expected[] = "0123456789abcdef";
    unsigned char actual[sizeof expected] = {0};
    FILE *f = fopen("NOVA.BIN", "rb");
    if (!f) return 0;
    size_t n = fread(actual, 1, sizeof actual, f);
    int ok = n == sizeof expected - 1 &&
             !memcmp(actual, expected, sizeof expected - 1) &&
             feof(f) && !ferror(f);
    if (fclose(f)) ok = 0;
    return ok;
}

static void compile_and_oracle(const Case *test, const char *source_dir,
                               const char *output_dir) {
    char source_path[4096], case_dir[4096], pe_path[4096], saved_path[4096];
    char metadata_path[4096], cwd[4096];
    size_t length = 0;
    unsigned char *text = NULL;
    NtArtifact artifact = {0};
    NovaHostImage mapped = {0};
    NovaContextV2 context = {0};
    int context_live = 0, changed_dir = 0;
    uint64_t got = UINT64_MAX, error_before_destroy = UINT64_MAX;
    int destroyed = 0;
    CHECK(path_join(source_path, sizeof source_path, source_dir, test->source),
          "source path fits");
    CHECK(path_join(case_dir, sizeof case_dir, output_dir, test->name),
          "case directory path fits");
    CHECK(path_join(pe_path, sizeof pe_path, case_dir, "core.EFI"),
          "PE path fits");
    CHECK(path_join(saved_path, sizeof saved_path, case_dir, "source.nova"),
          "snapshot path fits");
    CHECK(path_join(metadata_path, sizeof metadata_path, case_dir, "seed-c.json"),
          "metadata path fits");
    if (failures) goto cleanup;
    CHECK(mkdir(case_dir, 0777) == 0, "case directory must be fresh");
    if (failures) goto cleanup;
    text = read_source(source_path, &length);
    CHECK(text != NULL, "read real Nova fixture");
    if (!text) goto cleanup;
    CHECK(write_new(saved_path, text, length), "persist exact Nova source");
    if (failures) goto cleanup;

    NtFInput input = {test->source, (const char *)text, length};
    int ok = nova_compile_many_v2(&input, 1, &artifact);
    CHECK(ok && artifact.error.code == 0, "C seed compiles Nova ABI2 source");
    if (!ok || artifact.error.code) {
        fprintf(stderr, "SEED_COMPILE case=%s E%u source=%u line=%zu column=%zu %s\n",
                test->name, artifact.error.code, artifact.error.source_index,
                artifact.error.line, artifact.error.column, artifact.error.message);
        goto cleanup;
    }
    ++compiled;
    CHECK(artifact.text.bytes && artifact.text.size &&
          artifact.entry < artifact.text.size, "real NtArtifact text and entry");
    if (failures) goto cleanup;
    CHECK(nt_make_pe(&artifact) && artifact.error.code == 0,
          "existing PE writer emits real NtArtifact PE");
    CHECK(artifact.pe.bytes && artifact.pe.size > 1024,
          "real PE bytes exist");
    if (failures) goto cleanup;

    CHECK(getcwd(cwd, sizeof cwd) != NULL, "save oracle working directory");
    if (failures) goto cleanup;
    CHECK(chdir(case_dir) == 0, "isolate oracle file output in fresh case");
    if (failures) goto cleanup;
    changed_dir = 1;
    context_live = nova_context_init_v2(&context);
    CHECK(context_live, "initialize temporary C-runtime oracle");
    CHECK(context_live && nova_host_map(&artifact, &mapped),
          "map the compiled Nova entry with existing host API");
    if (!context_live || !mapped.entry) goto cleanup;
    got = mapped.entry(&context, NULL, 0);
    ++executed;
    error_before_destroy = context.error;
    CHECK(got == test->wanted_return, "Nova returned exact expected value");
    CHECK(error_before_destroy == test->wanted_error,
          "capture exact C-runtime error BEFORE destroy");
    if (test->roundtrip)
        CHECK(check_roundtrip_file(), "Nova file is exactly0123456789abcdef");
    nova_host_unmap(&mapped);
    destroyed = nova_context_destroy_v2(&context);
    context_live = 0;
    CHECK(destroyed, "C-runtime oracle cleans owned resources");
    CHECK(context.error == 0 && context.runtime == NULL,
          "destroy zeroes context; saved error remains independent");
    CHECK(chdir(cwd) == 0, "restore working directory");
    changed_dir = 0;
    if (failures) goto cleanup;
    CHECK(write_new(pe_path, artifact.pe.bytes, artifact.pe.size),
          "publish C_SEED_ORACLE PE only after exact oracle confirmation");
    if (failures) goto cleanup;

    char json[2048];
    int n = snprintf(json, sizeof json,
        "{\n  \"producer\": \"BOOTSTRAP_EXTERNAL_C\",\n"
        "  \"label\": \"C_SEED_ORACLE\",\n"
        "  \"scope\": \"runtime_interchangeability_only\",\n"
        "  \"case\": \"%s\",\n  \"source_bytes\": %zu,\n"
        "  \"text_bytes\": %zu,\n  \"rdata_bytes\": %zu,\n"
        "  \"data_bytes\": %zu,\n  \"entry_offset\": %zu,\n"
        "  \"pe_bytes\": %zu,\n  \"base_relocation_count\": %zu,\n"
        "  \"oracle_returned\": %" PRIu64 ",\n"
        "  \"oracle_error_before_destroy\": %" PRIu64 ",\n"
        "  \"oracle_destroyed\": true,\n  \"A8_selfhost_proven\": false\n}\n",
        test->name, length, artifact.text.size, artifact.rdata.size,
        artifact.data.size, artifact.entry, artifact.pe.size,
        artifact.base_relocation_count, got, error_before_destroy);
    CHECK(n > 0 && (size_t)n < sizeof json, "seed metadata fits");
    if (n > 0 && (size_t)n < sizeof json)
        CHECK(write_new(metadata_path, json, (size_t)n),
              "persist C-seed provenance and saved oracle result");
    printf("NATIVE_RUNTIME_C_SEED case=%s source=%zu text=%zu pe=%zu "
           "returned=%" PRIu64 " error_before_destroy=%" PRIu64 " cleanup=%d label=C_SEED_ORACLE\n",
           test->name, length, artifact.text.size, artifact.pe.size,
           got, error_before_destroy, destroyed);
cleanup:
    if (mapped.entry) nova_host_unmap(&mapped);
    if (context_live) CHECK(nova_context_destroy_v2(&context),
                            "cleanup C oracle after refusal");
    if (changed_dir) CHECK(chdir(cwd) == 0, "restore cwd after refusal");
    nt_artifact_free(&artifact);
    free(text);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s source-directory fresh-output-directory\n", argv[0]);
        return 2;
    }
    /* Relative paths must remain stable while each oracle temporarily chdirs. */
    CHECK(argv[1][0] == '/' && argv[2][0] == '/',
          "seed expects absolute WSL/POSIX source/output directories");
    if (failures) return 1;
    CHECK(mkdir(argv[2], 0777) == 0, "output root must be fresh and have an existing parent");
    if (failures) return 1;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        compile_and_oracle(&cases[i], argv[1], argv[2]);
        if (failures) break;
    }
    CHECK(compiled == 3 && executed == 3, "all three real Nova programs compile and run");
    printf("NTASM_NATIVE_RUNTIME_SEED checks=%u failures=%u compiled=%u oracle=%u "
           "producer=BOOTSTRAP_EXTERNAL_C A8_selfhost_proven=no\n",
           checks, failures, compiled, executed);
    return failures ? 1 : 0;
}

