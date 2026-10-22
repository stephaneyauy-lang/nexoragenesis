#include "../../../compiler/c/ntasm/formats/object.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks, failures;
#define CHECK(c, m)                                                            \
  do {                                                                         \
    ++checks;                                                                  \
    if (!(c)) {                                                                \
      ++failures;                                                              \
      fprintf(stderr, "FAIL: %s\n", m);                                        \
    }                                                                          \
  } while (0)
static uint32_t r32(const uint8_t *p) {
  return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
         (uint32_t)p[3] << 24;
}
/* ===========================================================================
 * THE REFUSAL/CONTROL PAIR.
 *
 * WHY IT IS HERE. Every expectation above is an ACCEPTANCE: the writer and
 * the reader agree. Meanwhile nt_object_read carries a dense validation
 * gauntlet that this gate never once reached -- the magic and version at
 * object.c:235, the symbol/relocation table layout at :240-245, per-section
 * layout and permissions, the nonzero-padding check. So the gate proved the
 * two halves AGREE and never proved the reader refuses anything, which is the
 * property a fabricated reader -- one that accepts every byte it is handed --
 * would satisfy identically.
 *
 * THE PAIR IS ONE BYTE. The census fixture: the symbol-table address word at
 * offset 40 set to 241 instead of 240. Nothing else in the 464-byte image is
 * touched, so the control is that same buffer unmutated and the refusal is
 * attributable to that byte alone.
 *
 * MEASURED, not transcribed -- and here the census was off by a category. It
 * said "nt_object_read error.code 24". 24 is the OFFSET the diagnostic
 * carries; the CODE is 800, the object-layer failure code that every fail()
 * in object.c stamps. So both are pinned: code 800 AND offset 24, which is a
 * STRICTER pin than either alone. The census's cheaper alternative (corrupt
 * the magic, which reports code 0) is not used, because a guard that reports
 * nothing cannot be pinned by its code.
 *
 * THE POISON: the decoded object is filled with 0xcc and must come back with
 * no symbols and no sections. nt_object_read refuses to write into a
 * non-empty output ("read output must be empty", object.c:231) and its header
 * promises "Failed reads remain empty", so on this path the meaningful
 * assertion is that no symbol table was materialised. A reader that returned
 * an error and still handed back a parsed object would pass `read == 0` and
 * fail these.
 * ======================================================================== */
static void read_refuses_mutated_table_layout(void) {
  uint8_t code[] = {0x48, 0xb8, 42, 0, 0, 0, 0, 0, 0, 0, 0xc3};
  uint8_t data[] = {42, 0, 0, 0, 0, 0, 0, 0};
  NtObjectSymbol symbols[] = {
      {"app.answer", "data:u64", 2, NT_OBJECT_VARIABLE, 0, 8},
      {"app.main", "fn()->u64;abi=nx64-abi-v0", 1,
       NT_OBJECT_EXPORT | NT_OBJECT_FUNCTION, 0, 11}};
  NtObject input = {0};
  input.target = 1;
  input.entry_symbol = 2;
  input.symbols = symbols;
  input.symbol_count = 2;
  input.sections[0] = (NtBuffer){code, sizeof code, sizeof code};
  input.sections[1] = (NtBuffer){data, sizeof data, sizeof data};
  NtBuffer bytes = {0};
  NtDiagnostic error;
  CHECK(nt_object_write(&input, &bytes, &error),
        "pair: the NXO image to be mutated was serialized");
  if (!bytes.bytes)
    return;

  /* THE CONTROL: the same buffer, unmutated. It must be accepted, and it must
   * really produce a symbol table -- otherwise "no symbols on the refusal arm"
   * would be a property of the harness rather than of the reader. */
  {
    NtObject decoded = {0};
    CHECK(nt_object_read(bytes.bytes, bytes.size, &decoded, &error),
          "pair control: the unmutated NXO reads back");
    CHECK(decoded.symbols != NULL && decoded.symbol_count == 2,
          "pair control: a real symbol table is materialised, so its absence "
          "on the refusal arm is a statement about the reader");
    nt_object_free(&decoded);
  }

  /* THE REFUSAL: ONE byte. offset 40, the symbol-table address: 240 -> 241. */
  {
    uint8_t *mutated = malloc(bytes.size);
    CHECK(mutated != NULL, "pair: mutation buffer allocated");
    if (!mutated) {
      free(bytes.bytes);
      return;
    }
    memcpy(mutated, bytes.bytes, bytes.size);
    CHECK(mutated[40] == 240,
          "pair: the byte about to be mutated is the 240 the writer emitted, "
          "so the mutation is 240 -> 241 and not a guess");
    mutated[40] = 241;
    /* Output MUST be zero-initialised: object.h says so, and object.c:231
     * refuses a non-empty output before it reads a single byte. Poisoning the
     * struct here would trip THAT guard and the gate would be measuring its
     * precondition rather than the layout check. */
    NtObject decoded = {0};
    int ok = nt_object_read(mutated, bytes.size, &decoded, &error);
    CHECK(!ok,
          "pair refusal: a symbol-table address of 241 is refused, one byte "
          "from the accepted 240");
    if (!ok) {
      CHECK(error.code == 800,
            "pair refusal: the exact failure code is 800, the object-layer code");
      CHECK(error.offset == 24,
            "pair refusal: the diagnostic names offset 24, the table-layout check");
      fprintf(stderr, "NXO_PAIR_REFUSAL code=%u offset=%zu %s\n", error.code,
              error.offset, error.message);
    }
    /* THE POISON. Nothing was materialised behind the refusal. */
    CHECK(decoded.symbols == NULL && decoded.symbol_count == 0,
          "pair refusal: no symbol table was materialised behind the refusal");
    CHECK(!decoded.sections[0].bytes && !decoded.sections[1].bytes &&
              !decoded.sections[2].bytes,
 "pair refusal: no section was materialised behind the refusal");
    nt_object_free(&decoded);
    free(mutated);
  }
  free(bytes.bytes);
}
int main(void) {
  uint8_t code[] = {0x48, 0xb8, 42, 0, 0, 0, 0, 0, 0, 0, 0xc3};
  uint8_t data[] = {42, 0, 0, 0, 0, 0, 0, 0};
  NtObjectSymbol symbols[] = {
      {"app.answer", "data:u64", 2, NT_OBJECT_VARIABLE, 0, 8},
      {"app.main", "fn()->u64;abi=nx64-abi-v0", 1,
       NT_OBJECT_EXPORT | NT_OBJECT_FUNCTION, 0, 11}};
  NtObject input = {0};
  input.target = 1;
  input.entry_symbol = 2;
  input.symbols = symbols;
  input.symbol_count = 2;
  input.sections[0] = (NtBuffer){code, sizeof code, sizeof code};
  input.sections[1] = (NtBuffer){data, sizeof data, sizeof data};
  NtBuffer bytes = {0};
  NtDiagnostic error;
  NtObject decoded = {0};
  int wrote = nt_object_write(&input, &bytes, &error);
  CHECK(wrote, "serialize code/data/symbols into NXO");
  if (wrote) {
    CHECK(bytes.size >= 400 && !memcmp(bytes.bytes, "NXOV0001", 8) &&
              r32(bytes.bytes + 8) == 1,
          "NXO magic and format version");
    CHECK(r32(bytes.bytes + 20) == 3 && r32(bytes.bytes + 24) == 2 &&
              r32(bytes.bytes + 88) == 2,
          "NXO independent header counts and entry symbol");
    CHECK(nt_object_read(bytes.bytes, bytes.size, &decoded, &error),
          "read structurally valid NXO");
    CHECK(decoded.symbol_count == 2 &&
              !strcmp(decoded.symbols[0].name, "app.answer") &&
              !strcmp(decoded.symbols[1].contract, symbols[1].contract),
          "typed symbol contracts roundtrip");
    CHECK(decoded.sections[0].size == sizeof code &&
              !memcmp(decoded.sections[0].bytes, code, sizeof code),
          "machine code payload roundtrip");
    CHECK(decoded.sections[1].size == 8 && decoded.sections[1].bytes[0] == 42,
          "data payload roundtrip");
  }
  read_refuses_mutated_table_layout();
  nt_object_free(&decoded);
  free(bytes.bytes);
  printf("NTASM_NXO_TESTS checks=%u failures=%u\n", checks, failures);
  return failures ? 1 : 0;
}
