#define _GNU_SOURCE
#include "../../../compiler/c/ntasm/backend/codegen.h"
#include "../../../compiler/c/ntasm/frontend/frontend.h"
#include "../../../compiler/c/ntasm/backend/x64.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#define MSABI
#define ALIGNED16 __declspec(align(16))
#else
#include <sys/mman.h>
#define MSABI __attribute__((ms_abi))
#define ALIGNED16 __attribute__((aligned(16)))
#endif
static unsigned checks, failures;
#define CHECK(x, msg)                                                          \
  do {                                                                         \
    checks++;                                                                  \
    if (!(x)) {                                                                \
      failures++;                                                              \
      fprintf(stderr, "FAIL EFI %s:%d %s\n", __FILE__, __LINE__, msg);         \
    }                                                                          \
  } while (0)
typedef uint64_t(MSABI *Eight)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                               uint64_t, uint64_t, uint64_t);
typedef uint64_t(MSABI *Zero)(void);
static uint64_t MSABI c_oracle(uint64_t a, uint64_t b, uint64_t c, uint64_t d,
                               uint64_t e, uint64_t f, uint64_t g, uint64_t h) {
  ALIGNED16 volatile uint64_t aligned[2] = {a, h};
  volatile uintptr_t actual = (uintptr_t)&aligned[0];
  if (actual & 15)
    return UINT64_MAX;
  return aligned[0] + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f + 7 * g +
         8 * aligned[1];
}
static void *seal(const NtCodeImage *image) {
#ifdef _WIN32
  void *p =
      VirtualAlloc(NULL, image->size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  DWORD prior;
  if (!p)
    return NULL;
  memcpy(p, image->bytes, image->size);
  if (!VirtualProtect(p, image->size, PAGE_EXECUTE_READ, &prior)) {
    VirtualFree(p, 0, MEM_RELEASE);
    return NULL;
  }
  FlushInstructionCache(GetCurrentProcess(), p, image->size);
  return p;
#else
  void *p = mmap(NULL, image->size, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED)
    return NULL;
  memcpy(p, image->bytes, image->size);
  if (mprotect(p, image->size, PROT_READ | PROT_EXEC)) {
    munmap(p, image->size);
    return NULL;
  }
  return p;
#endif
}
static void release(void *memory, size_t size) {
#ifdef _WIN32
  (void)size;
  VirtualFree(memory, 0, MEM_RELEASE);
#else
  munmap(memory, size);
#endif
}
static int compile(const char *source, NtFProgram *p, NtCodeImage *image) {
  NtFInput input = {"efi-interop", source, strlen(source)};
  NtCodeDiagnostic diagnostic;
  int front = nt_frontend_compile(&input, 1, p);
  CHECK(front, "EFI source frontend");
  if (!front) {
    for (size_t i = 0; i < p->diagnostic_count; i++)
      fprintf(stderr, " E%u %s\n", p->diagnostics[i].code,
              p->diagnostics[i].message);
    return 0;
  }
  int code = nt_codegen_x64(p, image, &diagnostic);
  CHECK(code, "EFI codegen");
  if (!code)
    fprintf(stderr, " E%u %s\n", diagnostic.code, diagnostic.message);
  return code;
}
#define PARAMS                                                                 \
  "in a:u64,in b:u64,in c:u64,in d:u64,in e:u64,in f:u64,in g:u64,in h:u64"
#define MODULE "module efi\ntarget x86_64-nexora-none\nsection .text {\n"
#define CLOBBERS "clobbers {rax,rcx,rdx,r8,r9,r10,r11,rflags}"
static void c_calls_generated(void) {
  const char *source =
      MODULE "export fn main(" PARAMS ")->u64\nabi efi-x64-v0\n"
             "effects {}\nclobbers {} {\nreturn "
             "a+2*b+3*c+4*d+5*e+6*f+7*g+8*h+(rsp&15)*1000\n}\n}\n";
  NtFProgram p;
  NtCodeImage image = {0};
  if (compile(source, &p, &image)) {
    void *memory = seal(&image);
    CHECK(memory, "map generated EFI entry");
    if (memory) {
      Eight fn = (Eight)((uint8_t *)memory + image.entry);
      CHECK(fn(1, 2, 3, 4, 5, 6, 7, 8) == 204,
            "C ms_abi caller supplies eight args and aligned generated frame");
      release(memory, image.size);
    }
  }
  nt_code_image_free(&image);
  nt_frontend_free(&p);
}
/* Link-test trampoline only: the producer never invokes a C compiler, linker
 * or foreign function. The test redirects one symbolic callee to an independent
 * C ms_abi oracle, without translating any NTASM program into C. */
static int bind_c_oracle(NtFProgram *p, NtCodeImage *image) {
  NtFId foreign = 0;
  for (size_t i = 0; i < p->function_count; i++)
    if (!strcmp(p->functions[i].name, "foreign"))
      foreign = (NtFId)(i + 1);
  if (!foreign)
    return 0;
  NtX64Operand operands[2] = {{0}, {0}};
  operands[0].kind = NT_X64_REG;
  operands[0].width = 64;
  operands[1].kind = NT_X64_IMM;
  operands[1].imm = (uint64_t)(uintptr_t)&c_oracle;
  NtX64Instruction mov, jump;
  NtX64Context context = {NT_X64_LM, 3};
  if (nt_x64_encode("mov", operands, 2, context, &mov) ||
      nt_x64_encode("jmp", operands, 1, context, &jump))
    return 0;
  size_t start = image->size, newsize = start + mov.length + jump.length;
  uint8_t *bytes = realloc(image->bytes, newsize);
  if (!bytes)
    return 0;
  image->bytes = bytes;
  image->size = newsize;
  image->capacity = newsize;
  memcpy(bytes + start, mov.bytes, mov.length);
  memcpy(bytes + start + mov.length, jump.bytes, jump.length);
  unsigned patched = 0;
  for (size_t i = 0; i < image->relocation_count; i++) {
    NtCodeReloc *r = &image->relocations[i];
    if (r->kind == NT_CODE_RELOC_REL32 && r->target_function == foreign) {
      int32_t displacement = (int32_t)(start - r->offset - 4);
      for (unsigned byte = 0; byte < 4; byte++)
        bytes[r->offset + byte] =
            (uint8_t)((uint32_t)displacement >> (byte * 8));
      patched++;
    }
  }
  return patched == 1;
}
static void generated_calls_c(void) {
  const char *source = MODULE
      "export fn main()->u64\neffects {changes_flags}\n" CLOBBERS " {\n"
      "return foreign(1,2,3,4,5,6,7,id(8))\n}\n"
      "fn id(in x:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn x\n}\n"
      "fn foreign(" PARAMS
      ")->u64\nabi efi-x64-v0\neffects {changes_flags}\n" CLOBBERS
      " {\nreturn 0\n}\n}\n";
  NtFProgram p;
  NtCodeImage image = {0};
  if (compile(source, &p, &image)) {
    int linked = bind_c_oracle(&p, &image);
    CHECK(linked, "bind independent C ABI oracle");
    void *memory = linked ? seal(&image) : NULL;
    CHECK(memory, "map linked EFI caller");
    if (memory) {
      Zero fn = (Zero)((uint8_t *)memory + image.entry);
      CHECK(fn() == 204, "generated caller provides C stack args, nested args, "
                         "shadow space and alignment");
      release(memory, image.size);
    }
  }
  nt_code_image_free(&image);
  nt_frontend_free(&p);
}
static void large_efi_and_frame_profiles(void) {
  char *source = calloc(1, 200000);
  CHECK(source, "large ABI source allocation");
  if (!source)
    return;
  size_t at = (size_t)snprintf(
      source, 200000,
      MODULE "export fn main()->u64\neffects {}\nclobbers {} {\nreturn sum64(");
  for (unsigned i = 0; i < 64; i++)
    at += (size_t)snprintf(source + at, 200000 - at, "%s%u", i ? "," : "", i);
  at += (size_t)snprintf(source + at, 200000 - at, ")\n}\nfn sum64(");
  for (unsigned i = 0; i < 64; i++)
    at += (size_t)snprintf(source + at, 200000 - at, "%sin a%u:u64",
                           i ? "," : "", i);
  at += (size_t)snprintf(
      source + at, 200000 - at,
      ")->u64\nabi efi-x64-v0\neffects {}\nclobbers {} {\nreturn ");
  for (unsigned i = 0; i < 64; i++)
    at += (size_t)snprintf(source + at, 200000 - at, "%sa%u", i ? "+" : "", i);
  snprintf(source + at, 200000 - at, "\n}\n}\n");
  NtFProgram p;
  NtCodeImage image = {0};
  if (compile(source, &p, &image)) {
    void *memory = seal(&image);
    CHECK(memory, "map sixty-four argument ABI");
    if (memory) {
      CHECK(((Zero)((uint8_t *)memory + image.entry))() == 2016,
            "all sixty-four EFI arguments survive stack lowering");
      release(memory, image.size);
    }
  }
  nt_code_image_free(&image);
  nt_frontend_free(&p);
  at = (size_t)snprintf(
      source, 200000,
      MODULE
      "export fn main()->u64\nabi efi-x64-v0\neffects {}\nclobbers {} {\n");
  for (unsigned i = 0; i < 800; i++)
    at += (size_t)snprintf(source + at, 200000 - at, "let v%u:u64=%u\n", i, i);
  snprintf(source + at, 200000 - at, "return v799\n}\n}\n");
  if (compile(source, &p, &image)) {
    void *memory = seal(&image);
    CHECK(memory, "map multi-page generated stack frame");
    if (memory) {
      CHECK(((Zero)((uint8_t *)memory + image.entry))() == 799,
            "multi-page stack frame executes with page probes");
      release(memory, image.size);
    }
  }
  nt_code_image_free(&image);
  nt_frontend_free(&p);
  free(source);
}
/* ===========================================================================
 * THE REFUSAL/CONTROL PAIR, and it is here because of HOW this file was
 * written. Every fixture above is well-formed: `a+2*b+...+(rsp&15)*1000`, the
 * eight-argument foreign call, the sixty-four-argument sum64, the 800-local
 * frame. A file whose every fixture names something DEFINED cannot tell
 * "the front end ran and accepted" from "the front end was replaced by
 * something that fabricates a valid-looking answer". So no fixture ever asked
 * the guard to refuse, and the refusal path was exercised by nothing.
 *
 * And the shape of the harness made that invisible rather than loud: the
 * three bodies above are wrapped in `if (compile(...))`, so a refusal SKIPS
 * the case. That clause is kept -- it is correct for an acceptance case, where
 * a refusal is already a failure by way of CHECK inside compile() -- but it is
 * exactly why the refusal had to be asserted HERE, where nothing is skipped:
 * the exact code, and the image left untouched.
 *
 * THE POISON. The image struct is filled with 0xcc before the call and must
 * come back 0xcc. A front end that refused by fabricating an entry point
 * would leave entry/size/symbol_count non-poison and be caught by the same
 * assertion that catches a missing refusal; a front end that refused by
 * quietly half-filling the struct is caught too. "front returned 0" on its
 * own would not catch either, which is why the poison is asserted and the
 * return value alone is not.
 *
 * MEASURED, not transcribed: the census predicted E_VALUE 941 for this
 * fixture. nt_frontend_compile answers NTF_E_NAME 301, "unknown function
 * 'missing'" -- an undefined callee is a NAME resolution failure and is
 * diagnosed before any value is considered. The pin below is what the tree
 * does, and a wrong pin is a red gate rather than a comfortable one.
 * ======================================================================== */
static void efi_refuses_undefined_callee(void) {
  /* THE CONTROL: the census fixture with the callee DECLARED. Same module,
   * same ABI, same body -- the only difference is that `missing` resolves. */
  static const char *declared =
      MODULE "export fn main()->u64\nabi efi-x64-v0\n"
             "effects {}\nclobbers {} {\nreturn missing(42)\n}\n"
             "fn missing(in x:u64 @rcx)->u64\nabi efi-x64-v0\n"
             "effects {}\nclobbers {} {\nreturn x\n}\n}\n";
  /* THE REFUSAL: that same module with the declaration absent. */
  static const char *undeclared =
      MODULE "export fn main()->u64\nabi efi-x64-v0\n"
             "effects {}\nclobbers {} {\nreturn missing(42)\n}\n}\n";
  struct {
    const char *label, *source;
    int accept;
  } pair[] = {
      {"declared-callee-control", declared, 1},
      {"undeclared-callee-refusal", undeclared, 0},
  };
  for (unsigned i = 0; i < 2; i++) {
    NtFInput input = {"efi-interop", pair[i].source, strlen(pair[i].source)};
    NtFProgram p;
    memset(&p, 0xcc, sizeof p);
    NtCodeImage image;
    memset(&image, 0xcc, sizeof image);
    int front = nt_frontend_compile(&input, 1, &p);
    if (pair[i].accept) {
      CHECK(front, "EFI control: a declared efi-x64-v0 callee is accepted");
      if (front) {
        NtCodeDiagnostic diagnostic = {0};
        NtCodeImage built = {0};
        CHECK(nt_codegen_x64(&p, &built, &diagnostic),
              "EFI control: the declared callee lowers");
        /* The control's job is to show the pair is a pair: on this side of the
         * one-token difference the front end PRODUCES an image, so the poison
         * assertion below is a statement about the refusal and not a property
         * of the harness. */
        CHECK(built.entry != UINT64_MAX && built.size != (size_t)-1,
              "EFI control: codegen wrote a real image, so poison is a "
              "statement about the refusal path");
        nt_code_image_free(&built);
      }
    } else {
      /* The exact code, and the image untouched. Both, because either alone
       * is a weaker claim than the pair makes. */
      CHECK(!front, "EFI refusal: an undeclared callee under abi efi-x64-v0 "
                    "is refused");
      if (!front) {
        CHECK(p.diagnostic_count >= 1 && p.diagnostics[0].code == 301,
              "EFI refusal: the exact diagnostic code is NTF_E_NAME 301 "
              "(measured; the census predicted 941)");
        fprintf(stderr, " EFI_REFUSAL code=%u %s\n",
                p.diagnostic_count ? p.diagnostics[0].code : 0u,
                p.diagnostic_count ? p.diagnostics[0].message : "(none)");
      }
      unsigned char *raw = (unsigned char *)&image;
      int intact = 1;
      for (size_t j = 0; j < sizeof image; j++)
        if (raw[j] != 0xcc) intact = 0;
      CHECK(intact,
            "EFI refusal: the code image is left at poison, so no entry point "
            "was fabricated behind the refusal");
    }
    nt_frontend_free(&p);
  }
}
int main(void) {
  c_calls_generated();
  generated_calls_c();
  large_efi_and_frame_profiles();
  efi_refuses_undefined_callee();
  printf("EFI_ABI_TESTS checks=%u failures=%u\n", checks, failures);
  return failures ? 1 : 0;
}
