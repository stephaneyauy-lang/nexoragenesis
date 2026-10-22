#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include "../../../compiler/c/ntasm/formats/object.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* NXO text accessor gate: canonical symbol name and contract bytes copied by
 * zero-based index and compared byte for byte against the C oracle. */

static unsigned checks, failures, cases;
#define CHECK(c, m) do { checks++; if (!(c)) { failures++; fprintf(stderr, "FAIL %s\n", m); } } while (0)
static const uint64_t guard = UINT64_C(0xcccccccccccccccc);
#define OUT_CAPACITY 4096
#define LENGTH_WORDS 4
#define MODE_NAME 0
#define MODE_CONTRACT 1

static char *load(const char *path, size_t *length) {
  FILE *f = fopen(path, "rb"); if (!f) return NULL;
  fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
  char *p = n >= 0 ? malloc((size_t)n + 1) : NULL;
  if (!p || fread(p, 1, (size_t)n, f) != (size_t)n) { free(p); fclose(f); return NULL; }
  fclose(f); p[n] = 0; *length = (size_t)n; return p;
}

typedef struct {
  uint64_t returned, runtime, out_bytes;
  uint8_t out[OUT_CAPACITY];
  uint64_t length[LENGTH_WORDS];
} Run;

static void run(const NovaHostImage *image, const NtBuffer *file, uint64_t file_size,
                uint64_t index, uint64_t mode, uint64_t out_bytes,
                uint64_t length_words, Run *r) {
  NovaContextV2 c = {0}; CHECK(nova_context_init_v2(&c), "context init");
  memset(r->out, 0xcc, sizeof r->out);
  for (unsigned i = 0; i < LENGTH_WORDS; i++) r->length[i] = guard;
  r->out_bytes = out_bytes;
  uint64_t ih = nova_borrow_v2(&c, file->bytes, file_size, 0);
  uint64_t oh = nova_borrow_v2(&c, r->out, out_bytes, 1);
  uint64_t lh = length_words ? nova_borrow_v2(&c, r->length, length_words * 8, 1)
                             : nova_borrow_v2(&c, NULL, 0, 1);
  /* A buf<T> crosses the boundary as handle plus element count; the borrow is
   * registered in bytes, so the flat slot carries the element count. */
  uint64_t args[] = {ih, file_size, index, oh, out_bytes, lh, length_words, mode};
  r->returned = image->entry(&c, args, 8);
  r->runtime = c.error;
  CHECK(nova_context_destroy_v2(&c), "context cleanup");
}

static void expect_text(const NovaHostImage *image, const NtBuffer *file, uint64_t index,
                        uint64_t mode, const char *expected) {
  Run r; cases++;
  uint64_t size = strlen(expected);
  run(image, file, file->size, index, mode, OUT_CAPACITY, LENGTH_WORDS, &r);
  CHECK(r.returned == 0, "text return code");
  CHECK(r.runtime == 0, "text runtime clean");
  CHECK(r.length[0] == size, "text reported length");
  CHECK(memcmp(r.out, expected, (size_t)size) == 0, "text bytes exact");
  int tail = 1;
  for (uint64_t i = size; i < OUT_CAPACITY; i++) if (r.out[i] != 0xcc) { tail = 0; break; }
  CHECK(tail, "text tail untouched");
  int spare = 1;
  for (unsigned i = 1; i < LENGTH_WORDS; i++) if (r.length[i] != guard) { spare = 0; break; }
  CHECK(spare, "length spare slots untouched");
}

static void expect_error(const NovaHostImage *image, const NtBuffer *file, uint64_t file_size,
                         uint64_t index, uint64_t mode, uint64_t out_bytes,
                         uint64_t length_words, uint64_t code, const char *what) {
  Run r; cases++;
  run(image, file, file_size, index, mode, out_bytes, length_words, &r);
  int bad = r.returned != code || r.runtime != 0;
  for (uint64_t i = 0; i < out_bytes; i++) if (r.out[i] != 0xcc) bad = 1;
  for (unsigned i = 0; i < LENGTH_WORDS; i++) if (r.length[i] != guard) bad = 1;
  checks++;
  if (bad) { failures++; fprintf(stderr, "FAIL %s: ret=%llu runtime=%llu want=%llu\n", what,
                                  (unsigned long long)r.returned, (unsigned long long)r.runtime,
                                  (unsigned long long)code); }
}

static char long_contract[321];

static void build_long_contract(void) {
  int written = snprintf(long_contract, sizeof long_contract, "data:[u64;16]@align8;ro=1;fill=");
  size_t n = (size_t)(written > 0 ? written : 0);
  while (n + 1 < sizeof long_contract) long_contract[n++] = 'x';
  long_contract[n] = 0;
}


int main(void) {
  build_long_contract();
  const char *paths[] = {
    "tests/nova/tests/nxo-inspect-text-entry.nova",
    "compiler/nova/inspectors/nxo_inspect.nova",
    "compiler/nova/formats/nxo/nxo.nova",
    "compiler/nova/formats/pe/pe.nova"};
  size_t sizes[4] = {0}; char *sources[4] = {0}; NtFInput inputs[4];
  for (unsigned i = 0; i < 4; i++) { sources[i] = load(paths[i], sizes + i); inputs[i] = (NtFInput){paths[i], sources[i], sizes[i]}; }
  CHECK(sources[0] && sources[1] && sources[2] && sources[3], "sources load");
  NtArtifact artifact = {0};
  int compiled = sources[0] && sources[1] && sources[2] && sources[3] && nova_compile_many_v2(inputs, 4, &artifact);
  CHECK(compiled, "Nova modules compile");
  if (!compiled) fprintf(stderr, "E%u %zu:%zu %s\n", artifact.error.code, artifact.error.line, artifact.error.column, artifact.error.message);
  NovaHostImage image = {0}; CHECK(compiled && nova_host_map(&artifact, &image), "image maps");
  if (image.memory) {
    uint8_t text[32] = {0}, rdata[8] = {0}, data[16] = {0};
    NtObjectSymbol symbols[] = {
      {"a", "v0", 3, NT_OBJECT_EXPORT | NT_OBJECT_VARIABLE, 0, 8},
      {"beacon_entry", "fn:u64->u64;abi=nx64-abi-v0", 1, NT_OBJECT_EXPORT | NT_OBJECT_FUNCTION, 0, 16},
      {"cm", "data:ptr", 3, NT_OBJECT_VARIABLE, 8, 8},
      {"m_very_long_symbol_name_here", "fn:(u64,u64)->u64;abi=nx64-abi-v0;pure=1", 1, NT_OBJECT_FUNCTION, 16, 8},
      {"zeta_table", long_contract, 2, NT_OBJECT_VARIABLE, 0, 8},
      {"zz_external", "fn:u64", 0, NT_OBJECT_IMPORT | NT_OBJECT_FUNCTION, 0, 0}};
    const size_t symbol_count = sizeof symbols / sizeof symbols[0];
    NtObjectReloc relocs[] = {
      {.section = 1, .kind = NT_OBJECT_REL32, .target = 2, .offset = 0, .addend = 0},
      {.section = 1, .kind = NT_OBJECT_REL32, .target = 5, .offset = 16, .addend = 0},
      {.section = 3, .kind = NT_OBJECT_DIR64, .target = 1, .offset = 0, .addend = 0},
      {.section = 3, .kind = NT_OBJECT_DIR64, .target = 3, .offset = 8, .addend = -1}};
    NtObject object = {0}; object.target = 1; object.entry_symbol = 2;
    object.symbols = symbols; object.symbol_count = symbol_count;
    object.relocations = relocs; object.relocation_count = sizeof relocs / sizeof relocs[0];
    object.sections[0] = (NtBuffer){text, 32, 32};
    object.sections[1] = (NtBuffer){rdata, 8, 8};
    object.sections[2] = (NtBuffer){data, 16, 16};
    int sorted = 1;
    for (size_t i = 1; i < symbol_count; i++)
      if (strcmp(symbols[i - 1].name, symbols[i].name) >= 0) sorted = 0;
    CHECK(sorted, "oracle names strictly sorted");
    NtBuffer file = {0}; NtDiagnostic error = {0};
    CHECK(nt_object_write(&object, &file, &error), "oracle writes multi-symbol NXO");
    if (file.bytes) {
      for (size_t i = 0; i < symbol_count; i++) {
        expect_text(&image, &file, i, MODE_NAME, symbols[i].name);
        expect_text(&image, &file, i, MODE_CONTRACT, symbols[i].contract);
      }
      uint64_t name_length = strlen(symbols[3].name), contract_length = strlen(long_contract);
      Run exact; cases++;
      run(&image, &file, file.size, 3, MODE_NAME, name_length, LENGTH_WORDS, &exact);
      CHECK(exact.returned == 0 && exact.runtime == 0, "exact fit name return");
      CHECK(exact.length[0] == name_length, "exact fit name length");
      CHECK(memcmp(exact.out, symbols[3].name, (size_t)name_length) == 0, "exact fit name bytes");
      Run exactc; cases++;
      run(&image, &file, file.size, 4, MODE_CONTRACT, contract_length, LENGTH_WORDS, &exactc);
      CHECK(exactc.returned == 0 && exactc.runtime == 0, "exact fit contract return");
      CHECK(exactc.length[0] == contract_length, "exact fit contract length");
      CHECK(memcmp(exactc.out, long_contract, (size_t)contract_length) == 0, "exact fit contract bytes");
      for (uint64_t m = 0; m < 2; m++) {
        expect_error(&image, &file, file.size, symbol_count, m, OUT_CAPACITY, LENGTH_WORDS, 810, "index equals count");
        expect_error(&image, &file, file.size, symbol_count + 7, m, OUT_CAPACITY, LENGTH_WORDS, 810, "index beyond count");
        expect_error(&image, &file, file.size, UINT64_MAX, m, OUT_CAPACITY, LENGTH_WORDS, 810, "index maximum");
      }
      expect_error(&image, &file, file.size, 3, MODE_NAME, name_length - 1, LENGTH_WORDS, 809, "short name buffer");
      expect_error(&image, &file, file.size, 3, MODE_NAME, 0, LENGTH_WORDS, 809, "empty name buffer");
      expect_error(&image, &file, file.size, 4, MODE_CONTRACT, contract_length - 1, LENGTH_WORDS, 809, "short contract buffer");
      expect_error(&image, &file, file.size, 4, MODE_CONTRACT, 0, LENGTH_WORDS, 809, "empty contract buffer");
      expect_error(&image, &file, file.size, 3, MODE_NAME, OUT_CAPACITY, 0, 809, "empty length buffer");
      expect_error(&image, &file, file.size, 4, MODE_CONTRACT, OUT_CAPACITY, 0, 809, "empty length buffer contract");
      expect_error(&image, &file, 0, 0, MODE_NAME, OUT_CAPACITY, LENGTH_WORDS, 800, "empty file");
      expect_error(&image, &file, 0, 0, MODE_CONTRACT, OUT_CAPACITY, LENGTH_WORDS, 800, "empty file contract");
      expect_error(&image, &file, 8, 0, MODE_NAME, OUT_CAPACITY, LENGTH_WORDS, 800, "undersized file");
      expect_error(&image, &file, 239, 0, MODE_NAME, OUT_CAPACITY, LENGTH_WORDS, 800, "below header size");
      expect_error(&image, &file, file.size - 1, 0, MODE_NAME, OUT_CAPACITY, LENGTH_WORDS, 800, "truncated file");
      expect_error(&image, &file, file.size - 1, 5, MODE_CONTRACT, OUT_CAPACITY, LENGTH_WORDS, 800, "truncated file contract");
      expect_error(&image, &file, file.size - 16, 2, MODE_NAME, OUT_CAPACITY, LENGTH_WORDS, 800, "truncated symbol table");
      uint8_t scratch[4096];
      memset(scratch, 0x5a, sizeof scratch);
      memcpy(scratch, "NXOV0001", 8);
      NtBuffer fake = {0}; fake.bytes = scratch; fake.size = sizeof scratch; fake.capacity = sizeof scratch;
      expect_error(&image, &fake, fake.size, 0, MODE_NAME, OUT_CAPACITY, LENGTH_WORDS, 800, "invalid magic body");
      expect_error(&image, &fake, fake.size, 0, MODE_CONTRACT, OUT_CAPACITY, LENGTH_WORDS, 800, "invalid magic body contract");
      scratch[20] = 9;
      expect_error(&image, &fake, fake.size, 1, MODE_NAME, OUT_CAPACITY, LENGTH_WORDS, 800, "invalid section count");
      if (file.size <= sizeof scratch) {
        memcpy(scratch, file.bytes, file.size);
        NtBuffer tampered = {0}; tampered.bytes = scratch; tampered.size = file.size; tampered.capacity = sizeof scratch;
        scratch[24] = 0xff; scratch[25] = 0xff; scratch[26] = 0xff; scratch[27] = 0xff;
        expect_error(&image, &tampered, tampered.size, 0, MODE_NAME, OUT_CAPACITY, LENGTH_WORDS, 800, "inflated symbol count");
        scratch[27] = 0x01;
        scratch[64] = 0xff; scratch[65] = 0xff; scratch[66] = 0xff; scratch[67] = 0x7f;
        expect_error(&image, &tampered, tampered.size, 1, MODE_CONTRACT, OUT_CAPACITY, LENGTH_WORDS, 800, "inflated string table");
        memset(scratch + 64, 0, 8);
        expect_error(&image, &tampered, tampered.size, 5, MODE_NAME, OUT_CAPACITY, LENGTH_WORDS, 800, "emptied string table");
      }
      free(file.bytes);
    }
  }
  if (image.memory)
    nova_host_unmap(&image);
  if (compiled)
    nt_artifact_free(&artifact);
  for (unsigned i = 0; i < 4; i++) free(sources[i]);
  printf("NTASM_NOVA_NXO_INSPECT_TEXT checks=%u failures=%u cases=%u\n", checks, failures, cases);
  return failures ? 1 : 0;
}
