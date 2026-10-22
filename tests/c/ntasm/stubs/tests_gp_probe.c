#define efi_main probe_efi_main
#include "../../../../compiler/c/ntasm/formats/gp_probe.c"
#undef efi_main
/* <stdio.h> cannot be included in this translation unit. gp_probe.c defines
   `struct FILE` as the UEFI file protocol, and stdio.h typedefs FILE to
   struct _IO_FILE: the same name, two unrelated types, so the header is a
   hard compile error rather than a shadow. These two declarations name the
   libc symbols directly instead. Both are pointers at the ABI, so the call
   below is the ordinary fprintf to the ordinary stderr. */
extern int fprintf(void *stream, const char *format, ...);
extern void *stderr;
static unsigned checks, failures;
/* The name was already here, at every call site, and was thrown away by
   (void)(n). A check that counts a failure and prints nothing is a red a
   reader cannot attribute: the run goes red, the log is empty, and the only
   thing the reader can do is guess which of the five encodings moved. The
   counter and the message are now the same statement, so there is no path on
   which one happens without the other. */
#define CHECK(c, n)                                                            \
  do {                                                                         \
    checks++;                                                                  \
    if (!(c)) {                                                                \
      failures++;                                                              \
      fprintf(stderr, "FAIL %s\n", (n));                                       \
    }                                                                           \
  } while (0)
static int same(const uint8_t *a, const uint8_t *b, size_t size) {
  while (size--)
    if (*a++ != *b++)
      return 0;
  return 1;
}
int main(void) {
  static const uint8_t sidt[] = {0x0f, 0x01, 0x09, 0xc3};
  static const uint8_t lidt[] = {0x0f, 0x01, 0x19, 0xc3};
  static const uint8_t cs[] = {0x31, 0xc0, 0x66, 0x8c, 0xc8, 0xc3};
  static const uint8_t flags[] = {0x9c, 0x58, 0xc3};
  static const uint8_t gp[] = {0xb8,0xf8,0xff,0,0,0x9c,0x41,0x58,0x8e,0xd8,0x9c,0x58,0x4c,0x31,0xc0,0xc3};
  CHECK(sizeof(sidt_code) == sizeof(sidt) &&
            same(sidt_code, sidt, sizeof(sidt)),
        "SIDT [rcx]; ret encoding");
  CHECK(sizeof(lidt_code) == sizeof(lidt) &&
            same(lidt_code, lidt, sizeof(lidt)),
        "LIDT [rcx]; ret encoding");
  CHECK(sizeof(cs_code) == sizeof(cs) && same(cs_code, cs, sizeof(cs)),
        "read CS encoding");
  CHECK(sizeof(flags_code) == sizeof(flags) &&
            same(flags_code, flags, sizeof(flags)),
        "read RFLAGS encoding");
  CHECK(sizeof(gp_code) == sizeof(gp) && same(gp_code, gp, sizeof(gp)),
        "out-of-GDT MOV DS #GP flags observer encoding");
  return failures ? 1 : 0;
}
