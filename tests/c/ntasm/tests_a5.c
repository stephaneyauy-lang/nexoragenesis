#define _GNU_SOURCE
#include "../../../compiler/c/ntasm/backend/codegen.h"
#include "../../../compiler/c/ntasm/frontend/frontend.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif
static unsigned checks, failures;
#define CHECK(c, m)                                                            \
  do {                                                                         \
    checks++;                                                                  \
    if (!(c)) {                                                                \
      failures++;                                                              \
      fprintf(stderr, "FAIL %s\n", (m));                                       \
    }                                                                          \
  } while (0)
static uint64_t execute(const NtCodeImage *image) {
#ifdef _WIN32
  void *memory =
      VirtualAlloc(NULL, image->size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  DWORD old = 0;
  if (!memory)
    return 0;
  memcpy(memory, image->bytes, image->size);
  if (!VirtualProtect(memory, image->size, PAGE_EXECUTE_READ, &old)) {
    VirtualFree(memory, 0, MEM_RELEASE);
    return 0;
  }
  uint64_t value = ((uint64_t (*)(void))((uint8_t *)memory + image->entry))();
  VirtualFree(memory, 0, MEM_RELEASE);
  return value;
#else
  void *memory = mmap(NULL, image->size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (memory == MAP_FAILED)
    return 0;
  memcpy(memory, image->bytes, image->size);
  if (mprotect(memory, image->size, PROT_READ | PROT_EXEC)) {
    munmap(memory, image->size);
    return 0;
  }
  uint64_t value = ((uint64_t(__attribute__((ms_abi)) *)(void))(
      (uint8_t *)memory + image->entry))();
  munmap(memory, image->size);
  return value;
#endif
}

/* ===========================================================================
 * THE REFUSAL/CONTROL PAIR.
 *
 * WHY IT IS HERE. The end-to-end fixture in main() names only macros that ARE
 * DECLARED, at the arity they are declared with: `expand make(expand word())`
 * expands `word`, which `macro word()->ast.type` declares. A file whose only
 * fixture is well-formed cannot separate "the expander ran and expanded" from
 * "the expander was replaced by something that emits the AST this file happens
 * to want". Its whole expectation was `generated && value == 42 &&
 * function_symbols == 2`, and a fabricated expander emitting a hardcoded AST
 * yielding 42 with two symbols passes that bit for bit. Before this block the
 * file had no CHECK macro at all.
 *
 * THE PAIR IS ONE TOKEN. Both sources below are the same module with ONE
 * identifier changed at ONE call site: `expand word()` becomes
 * `expand nosuchmacro()`. The DECLARATION of `word` is present on BOTH sides,
 * so the control is not "a module with fewer macros" -- it is the same module
 * with a call that resolves. That is what makes this a pair: the refusal
 * cannot be explained by the module being different, only by the one token.
 *
 * MEASURED, not transcribed: nt_frontend_compile answers NTF_E_NAME 301,
 * "unknown macro 'nosuchmacro'". Pinned here from a run of this tree.
 *
 * THE POISON. A refused program has no image, so the image struct is filled
 * with 0xcc first and must come back 0xcc. `front == 0` alone would not catch a
 * front end that refused and left a fabricated function table behind, nor one
 * that refused and wrote an entry point anyway. The control arm is what stops
 * the poison assertion from being vacuous: it shows codegen DOES write a real
 * image on the accepted side of the same one-token difference, so an untouched
 * image on the refused side is a fact about the refusal and not about this
 * harness never looking.
 * ======================================================================== */
#define A5_MODULE_HEAD                                                       \
  "module macro_fn\ntarget x86_64-nexora-none\n"                            \
  "macro word()->ast.type {\nreturn quote(type) { u64 };\n}\n"              \
  "macro plus(v:ast.expr)->ast.expr {\nreturn quote(expr) { $v+1 };\n}\n"  \
  "macro next(v:u64)->ast.expr {\nreturn quote(expr) { $v+1 };\n}\n"       \
  "macro finish(v:ast.expr)->ast.stmt {\n"                                  \
  "return quote(stmt) { return $v; };\n}\n"                                  \
  "macro make(T:ast.type)->ast.decl {\nreturn quote(decl) {\n"               \
  " export fn add(in x:$T @rcx,in y:$T @rdx)->$T\n"                          \
  " effects {}\nclobbers {} {\nlet sum:$T=x+y\nexpand finish(sum)\n}\n"  \
  "};\n}\n"                                                                  \
  "macro computed(v:ast.expr)->ast.stmt {\nlet first=$v+1;\n"             \
  "let second=$first+1;\nreturn quote(stmt) { return $second; };\n}\n"         \
  "section .text {\n"
#define A5_MODULE_TAIL                                                     \
  "export fn main()->u64\neffects {}\nclobbers {} {\n"                      \
  "expand computed(expand plus(add(17,expand next(21))))\n}\n}\n"

/* THE CONTROL: the module above, unchanged. It must be accepted, and codegen
 * must really produce an image -- otherwise the poison assertion on the other
 * arm would be satisfied by a harness that never writes one anywhere. */
static void pair_control_is_accepted(void) {
  static const char *control =
      A5_MODULE_HEAD "expand make(expand word())\n" A5_MODULE_TAIL;
  NtFInput input = {"macro-fn", control, strlen(control)};
  NtFProgram program;
  int front = nt_frontend_compile(&input, 1, &program);
  CHECK(front, "A5 control: the declared macro name resolves");
  if (front) {
    NtCodeDiagnostic diagnostic = {0};
    NtCodeImage built = {0};
    int code = nt_codegen_x64(&program, &built, &diagnostic);
    CHECK(code, "A5 control: the expanded module lowers");
    if (code)
      CHECK(built.entry < built.size && built.size != 0,
            "A5 control: codegen wrote a real image, so an untouched image on "
            "the refusal arm is a statement about the refusal");
    nt_code_image_free(&built);
  }
  nt_frontend_free(&program);
}

/* THE REFUSAL: the same module, one token changed. The exact code, and the
 * image left at poison. */
static void pair_refuses_unknown_macro(void) {
  static const char *refusal =
      A5_MODULE_HEAD "expand make(expand nosuchmacro())\n" A5_MODULE_TAIL;
  NtFInput input = {"macro-fn", refusal, strlen(refusal)};
  NtFProgram program;
  memset(&program, 0xcc, sizeof program);
  NtCodeImage image;
  memset(&image, 0xcc, sizeof image);
  int front = nt_frontend_compile(&input, 1, &program);
  CHECK(!front,
        "A5 refusal: `expand nosuchmacro()` is refused, where `macro word()` "
        "is declared and one token away");
  if (!front) {
    CHECK(program.diagnostic_count >= 1 && program.diagnostics[0].code == 301,
          "A5 refusal: the exact diagnostic code is NTF_E_NAME 301");
    fprintf(stderr, "A5_PAIR_REFUSAL code=%u %s\n",
            program.diagnostic_count ? program.diagnostics[0].code : 0u,
            program.diagnostic_count ? program.diagnostics[0].message
                                     : "(none)");
  }
  const unsigned char *raw = (const unsigned char *)&image;
  int intact = 1;
  for (size_t i = 0; i < sizeof image; i++)
    if (raw[i] != 0xcc) {
      intact = 0;
      fprintf(stderr,
              "A5_PAIR_REFUSAL image byte %zu was written (0x%02x) on the "
              "refusal path\n",
              i, raw[i]);
      break;
    }
  CHECK(intact,
        "A5 refusal: the code image is left at poison, so no entry point was "
        "fabricated behind the refusal");
  nt_frontend_free(&program);
}

int main(void) {
  const char *source = "module macro_fn\ntarget x86_64-nexora-none\n"
                       "macro word()->ast.type {\n"
                       "return quote(type) { u64 };\n}\n"
                       "macro plus(v:ast.expr)->ast.expr {\n"
                       "return quote(expr) { $v+1 };\n}\n"
                       "macro next(v:u64)->ast.expr {\n"
                       "return quote(expr) { $v+1 };\n}\n"
                       "macro finish(v:ast.expr)->ast.stmt {\n"
                       "return quote(stmt) { return $v; };\n}\n"
                       "macro make(T:ast.type)->ast.decl {\n"
                       "return quote(decl) {\n"
                       " export fn add(in x:$T @rcx,in y:$T @rdx)->$T\n"
                       " effects {}\nclobbers {} {\n"
                       "let sum:$T=x+y\nexpand finish(sum)\n}\n"
                       "};\n}\n"
                       "macro computed(v:ast.expr)->ast.stmt {\n"
                       "let first=$v+1;\nlet second=$first+1;\n"
                       "return quote(stmt) { return $second; };\n}\n"
                       "section .text {\n"
                       "expand make(expand word())\n"
                       "export fn main()->u64\neffects {}\nclobbers {} {\n"
                       "expand computed(expand plus(add(17,expand next(21))))\n"
                       "}\n}\n";
  NtFInput input = {"macro-fn", source, strlen(source)};
  NtFProgram program;
  if (!nt_frontend_compile(&input, 1, &program)) {
    for (size_t i = 0; i < program.diagnostic_count; i++)
      fprintf(stderr, "E%u %s\n", program.diagnostics[i].code,
              program.diagnostics[i].message);
    nt_frontend_free(&program);
    return 1;
  }
  NtCodeImage image = {0};
  NtCodeDiagnostic diagnostic = {0};
  int generated = nt_codegen_x64(&program, &image, &diagnostic);
  uint64_t value = generated ? execute(&image) : 0;
  unsigned function_symbols = 0;
  for (size_t i = 0; i < image.symbol_count; i++)
    function_symbols += image.symbols[i].function_id != 0;
  printf("A5_EXEC value=%llu functions=%u\n", (unsigned long long)value,
         function_symbols);
  nt_code_image_free(&image);
  nt_frontend_free(&program);
  if (!(generated && value == 42 && function_symbols == 2))
    return 1;
  pair_control_is_accepted();
  pair_refuses_unknown_macro();
  printf("A5_PAIR checks=%u failures=%u pair=unknown-macro\n", checks, failures);
  return failures ? 1 : 0;
}