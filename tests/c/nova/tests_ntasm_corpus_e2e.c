/* ===========================================================================
 * NTASM_NOVA_CORPUS_E2E -- lot 37. The corpus, END TO END, per program.
 *
 * WHY THIS FILE EXISTS, and the sentence it replaces.
 *
 * "There are N programs in examples/ntasm-v0/ and M gates name one of them."
 * Both numbers were true and neither was evidence that a program RUNS. A gate
 * that NAMES a source assembles it and stops at the bytes; the word "executed"
 * was available for a run that stopped at an exit code. So this file is built
 * around the distinction the lot turns on:
 *
 *   compiled  -- nt_frontend_compile accepted the source
 *   linked    -- nt_make_pe produced a PE, i.e. an entry RVA and a DIR64 table
 *   executed  -- the PE was LOADED AT AN ADDRESS THAT IS NOT ITS PREFERRED
 *                ONE, every DIR64 site was REBASED BY THE DELTA, the image was
 *                mapped PROT_READ|PROT_EXEC, and the entry was CALLED
 *   RESULT    -- the u64 that came back, printed
 *
 * THE REBASE IS THE POINT, and it is the step every other mapper in this tree
 * SKIPS. Measured 30 September 2026: no file under bootstrap/, tools/ or out/
 * contains a load-time relocation loop. nt_make_pe (ntasm.c:312) bakes
 * 0x140001000+entry into the .rdata anchor and object_materialize.c:60-76 bakes
 * every DIR64 as an absolute 0x140000000+target. nova_host_map (run_host.c:29)
 * papers over exactly ONE of those sites -- the anchor -- by writing the live
 * entry address over it, and leaves every other absolute slot dangling. A PE
 * mapped at 0x140000000 would therefore "work" without a single relocation
 * being correct, which is why this file NEVER maps at the preferred base: the
 * load bias is a fixed, deliberately non-zero constant, and a program that
 * reads an absolute address proves the rebase happened because the ONLY way to
 * get the right number is to have added the delta.
 *
 * WHAT "OBSERVABLE FROM OUTSIDE" MEANS HERE, stated because the lot requires it
 * and because a return value alone would not be enough. Every executed row
 * prints the u64 the machine returned AND, where the program has a .data
 * section, the bytes of that .data read back out of the mapped image AFTER the
 * call. A program whose whole result is a store into its own .data is read back
 * out of the image rather than trusted, so "it ran" and "it produced this" are
 * two different assertions and both are made.
 *
 * WHAT THIS FILE DOES NOT CLAIM. It is a host process calling a mapped PE
 * entry, not firmware. It makes no QEMU claim and no boot record, and the two
 * must never be added together -- the same distinction tests_ntasm_comptime.c
 * states for itself. It also says nothing about the 352 bytes by which
 * object+link differs from assemble for a two-module program: the route driven
 * here is the whole-program one, `assemble`.
 * ========================================================================= */
#define _GNU_SOURCE
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include "../../../compiler/c/ntasm/frontend/ntasm.h"
#include "../../../compiler/c/ntasm/formats/object.h"
#include "../../../compiler/c/ntasm/formats/pe.h"
#include "../../../compiler/c/ntasm/formats/pe_layout.h"
#include "../../../compiler/c/ntasm/frontend/frontend.h"
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
static unsigned checks, failures, cases;

/* The load bias. NOT a page size, not 0, and not the image base: a loader that
 * chose the preferred address would make every rebase check below vacuous. The
 * value is 0x7f0000000000 -- far above anything the producer emits, below the
 * x86-64 canonical ceiling, and 64 KiB page aligned because the image is. */
#define LOAD_BIAS UINT64_C(0x7f0000000000)
/* The two HOST mappings, pinned far from LOAD_BIAS and from each other. All
 * three are MAP_FIXED_NOREPLACE and all three assert the address they asked
 * for, so an overlap is a refusal rather than a silent overwrite. Measured
 * mappable on this host; a host where they are not is a host that says so
 * instead of one that corrupts an image. */
#define STACK_BIAS UINT64_C(0x200000000000)
#define CALLPAGE_BIAS UINT64_C(0x300000000000)
/* The shape of an NTASM entry: a position independent ms_abi function of no
 * arguments returning u64 in RAX. docs/guides/ntasm-cli.md section 2 states it, and
 * tests_object_separate.c calls a product image through exactly this cast. */
typedef uint64_t(__attribute__((ms_abi)) W74Entry)(void);


#define CHECK(c, m)                                                             \
  do {                                                                          \
    checks++;                                                                   \
    if (!(c)) {                                                                 \
      failures++;                                                               \
      fprintf(stderr, "FAIL %s\n", (m));                                        \
    }                                                                           \
  } while (0)

static char *loadf(const char *p, size_t *n) {
  FILE *f = fopen(p, "rb");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END);
  long z = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *b = z >= 0 ? malloc((size_t)z + 1) : NULL;
  if (!b || fread(b, 1, (size_t)z, f) != (size_t)z) {
    free(b);
    fclose(f);
    return NULL;
  }
  fclose(f);
  b[z] = 0;
  *n = (size_t)z;
  return b;
}

/* The reference materializer allocates five buffers and frees none of them, so
 * every harness that drives it carries this copy of the convention rather than
 * a second way of doing it. Same shape as tests_ntasm_comptime.c:93. */
static void free_artifact(NtArtifact *a) {
  if (a->pe.bytes) { free(a->pe.bytes); a->pe.bytes = NULL; }
  if (a->text.bytes) { free(a->text.bytes); a->text.bytes = NULL; }
  if (a->rdata.bytes) { free(a->rdata.bytes); a->rdata.bytes = NULL; }
  if (a->data.bytes) { free(a->data.bytes); a->data.bytes = NULL; }
  free(a->base_relocations);
  memset(a, 0, sizeof *a);
}

/* ===========================================================================
 * THE LOADER. Three steps, and each one is separately counted so a reader can
 * see WHICH of them carried the program.
 *
 * 1. LOAD. The PE is a FILE image; a mapped image is laid out by RVA, not by
 *    file offset. Copying the file to base+0 would put .text at base+1024
 *    instead of base+4096 and every absolute address would be wrong by an
 *    amount no rebase can fix, so the section table is walked and each section
 *    is copied to base+VirtualAddress. This is the step that makes the load
 *    bias meaningful.
 * 2. REBASE. Walk .reloc exactly as a PE loader does: a block header
 *    (PageRVA, SizeOfBlock) then 16-bit entries whose top 4 bits are the type
 *    and low 12 the offset in the page. Type 10 is IMAGE_REL_BASED_DIR64 and
 *    the site is 8 bytes. The value there was baked as 0x140000000+target, so
 *    adding (chosen_base - 0x140000000) makes it correct AT chosen_base. The
 *    number of sites touched is RETURNED, because a rebase that touched nothing
 *    must not be reported as a rebase that worked.
 * 3. EXECUTE. mprotect the whole image PROT_READ|PROT_EXEC and call the entry
 *    as a nullary ms_abi function returning u64. The image is a .data-bearing
 *    one, so the data region is left writable: a program that stores to its own
 *    .data SIGSEGVs under a whole-image RX seal, which is why this does NOT use
 *    the single mprotect tests.c:67-68 makes.
 * ========================================================================= */
typedef struct {
  int loaded;        /* the image was mapped at a non-preferred address     */
  int rebased;       /* every DIR64 site was corrected by the delta          */
  int called;        /* the entry was entered and returned                   */
  unsigned sites;    /* how many DIR64 sites the rebase actually wrote       */
  uint64_t base;     /* where it was mapped                                  */
  uint64_t returned; /* what the machine put in RAX                          */
  uint8_t data[64];  /* the image's .data, read back AFTER the call          */
  size_t data_size;  /* how many bytes of it are meaningful                  */
  char note[128];    /* why a step did not happen, when it did not            */
} Loaded;

static uint32_t r32(const uint8_t *b) {
  return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
         ((uint32_t)b[3] << 24);
}
static uint16_t r16(const uint8_t *b) {
  return (uint16_t)((uint32_t)b[0] | ((uint32_t)b[1] << 8));
}
static uint64_t r64(const uint8_t *b) {
  uint64_t v = 0;
  for (unsigned i = 0; i < 8; i++) v |= (uint64_t)b[i] << (i * 8);
  return v;
}

/* ===========================================================================
 * THE GUARD STACK. A pthread with an explicitly sized stack and a PROT_NONE
 * guard page beneath it, because the thing being called is machine code whose
 * frame size this file does not know and must not assume.
 *
 * WHY A THREAD AND NOT A BIGGER LOCAL BUFFER. An alloca'd array large enough
 * would work until a program recursed, and the failure mode of running out of
 * stack is a write below the mapping, which on this build is a silent
 * corruption rather than a trap. The guard page turns that into a fault at the
 * boundary, and a thread's stack is sized by the caller of pthread_attr_setstack
 * rather than by whatever the compiler happened to leave on the frame.
 * ========================================================================= */
#define GUARD_BYTES (size_t)65536
#define STACK_BYTES ((size_t)8 * 1024 * 1024)

typedef struct {
  W74Entry *fn;
  uint64_t result;
  int called;
} Call;

/* The Call record lives in a MMAP'd page, never in a C frame.
 *
 * MEASURED, and this is the whole reason. The first two versions kept it in a
 * local: a local of run_on_guard_stack, then a local of guard_thread. A framed
 * NTASM body pushes thirteen saved registers and rbp and then, at its epilogue,
 * restores them from addresses BELOW the stack pointer it was given -- and the
 * return address it finally `ret`s to is a value the body can overwrite,
 * because the body's frame is larger than the gap between the entry's rsp and
 * the host frame that called it. The symptom was precise and it named itself:
 * UBSan reported a member access at 0x2a for a `struct Call` whose real
 * address was 0x775926511080, and 0x2a is 42, the value the PREVIOUS member
 * returned. So the record was being written where a spilled 42 landed.
 *
 * Putting the record in its own page, at an address the image cannot reach
 * relative to its stack, removes the coupling entirely: the image's frame can
 * be any size at all and the record survives, because nothing in the image
 * holds a pointer to it. */
static void *g_call_page;

/* ===========================================================================
 * THE STATE HUNT, RESOLVED. What the previous note at this site called "the
 * 17th member faults with a struct Call pointer equal to 0x2a" was never the
 * thread, the mapping, or the PREVIOUS member's result. All three were
 * eliminated by measurement, and the real carrier was found by perturbation.
 *
 * THE THREE ELIMINATIONS, each a run and not an argument:
 *
 *  1. NOT THE PREVIOUS MEMBER. `memory-space-user-data` faults with 0x2a when
 *     it is the ONLY member selected. It needs no predecessor to break, so
 *     nothing carried across a member boundary caused it.
 *  2. NOT THE THREAD. W74_NO_THREAD=1, which calls the image directly from
 *     this frame with no pthread and no guard stack, stops at the same member
 *     with the same address.
 *  3. NOT THE MAPPING. A canary over all 4096 bytes of the call page, filled
 *     immediately before each image is entered and checked immediately after,
 *     never fired: the image never writes into the record's page. The record
 *     was never corrupted. It was REPLACED.
 *
 * WHAT 0x2a ACTUALLY IS, by perturbation rather than by reading. The member is
 * `examples/ntasm-v0/corpus-e2e/memory-space-user-data.ntasm`, whose body is
 * `load rbx,[base]` then `add rbx,12`, with base:u64=30. Rewriting `base` IN
 * MEMORY ONLY and watching the fault address move:
 *
 *     base=30     rbx=42      fault 0x00000000002a
 *     base=1000   rbx=1012    fault 0x0000000003f4
 *     base=7      rbx=19      fault 0x000000000013
 *     base=65536  rbx=65548   fault 0x00000001000c
 *
 * The address IS base+12, exactly: the value the body leaves in rbx.
 *
 * THE CARRIER, therefore, is rbx. objdump of this file's own guard_thread shows
 * the compiler holding the record pointer there across the call into the
 * image:
 *
 *     mov  %rdi,%rbx          ; c = arg
 *     ...
 *     call *%rax              ; the image
 *     mov  %rax,%r12
 *     mov  %r12,0x8(%rbx)     ; c->result -- and rbx is no longer c
 *
 * The image is entered through `W74Entry`, a plain `ms_abi` function pointer,
 * so its frame is the product's and the caller's rbx is callee-saved by the
 * ordinary convention the C compiler is entitled to rely on. The product's
 * epilogue (codegen.c:899-906) SKIPS the pop for any register the function
 * declares in its own `clobbers`:
 *
 *     if ((FN(...).clobbers | nt_conformance_output_registers(...)) & (1<<reg))
 *       lea 4,[rbp+8]        ; skip the restore
 *     else
 *       pop reg
 *
 * and `memory-space-user-data` declares `clobbers {rax,rbx,rflags}`. So the
 * image returns rbx holding its own arithmetic, the C caller reads that as a
 * pointer, and `c->result = ...` writes through 42. That is why the address
 * was 42, and why it was 42 rather than the PREVIOUS member's value: 42 is
 * what THIS member computes.
 *
 * IS THE PRODUCT WRONG? No, and the reason is in the contract rather than in
 * this file's opinion. `clobbers` is a declaration of what a function does NOT
 * preserve (spec/ntasm/ntasm.md section 8.2: "l'ensemble des registres et etats
 * machine dont la valeur d'entree n'est pas preservee au point de retour"), and
 * spec/ntasm/ntasm.md:2343-2346 states the rule exactly: a `clobbers` family must be
 * one the nx64 frame pushes at entry and may therefore decline to restore.
 * rbx is in `saved_registers[]` (codegen.c:93-94), so declaring it and not
 * restoring it is the product doing exactly what it declared. The product is
 * CORRECT here. This member is the only one in the corpus whose source names
 * rbx, which is why twenty members ran and the twenty-first did not.
 *
 * IS THE HARNESS WRONG? Yes, and it is this file. `guard_thread` compiled to C
 * that keeps a live pointer in rbx across the call, which is legal only if the
 * callee preserves rbx. The harness called a callee whose own declaration says
 * it may not, and read the clobbered register as a pointer. That is the defect
 * and it is here, not in codegen.c, frontend.c or nova.c.
 *
 * THE REPAIR, and the rule it follows: the harness must not DEPEND on a
 * register the callee has declared it may destroy. So nothing of this frame
 * crosses the call except the return value in rax. The record pointer is
 * RE-DERIVED from the global AFTER the image returns, and the thread argument
 * is CHECKED against that global -- so a genuinely wrong pointer is still a
 * reported failure rather than a silent substitution.
 *
 * AND IT REPORTS RATHER THAN PASSES OVER. `g_rbx_destroyed` records whether the
 * callee actually destroyed rbx on this call, and CONTROL 4 below asserts the
 * instrument SEES it. A repair that made this gate stop crashing by making it
 * stop looking would leave every green here meaningless; control 4 is what
 * distinguishes the two, and it is proven to bite in the negative. */

/* NO_ASAN, and the reason is measured rather than stylistic.
 *
 * The emitted NTASM frame begins `pushfq; push r13..r5; push rbp; mov rbp,rsp`
 * and ends `mov rsp,rbp; pop rbp; popfq; ret`. It is a COMPLETE, BALANCED
 * frame -- verified on the bytes, 368 of them for frame-omission, epilogue
 * 5d 41 5f ... 9d c3. Called through an ASAN-instrumented C trampoline it
 * still faulted, with bp = 0x2a, which is 42: the value the body stores. So
 * the fault is in the CALLER's instrumentation, not the image -- ASAN poisons
 * the red zone below the trampoline's frame, the image's prologue writes its
 * thirteen saved registers into exactly that poisoned band, and the write is
 * what traps. The image is correct; the instrument under it is not.
 *
 * So this one function opts out of the sanitizer. Everything that MEASURES --
 * the census, the rebase, the result column, the three controls -- stays
 * instrumented, and the exclusion is one function rather than the file. */
/* A REAL C FUNCTION WITH A REAL FRAME, which the image returns INTO. The
 * measurement that forced this: called through a bare function pointer, the
 * fault carried bp = 0x2a -- 42, the value the body stores -- so the image was
 * running against a caller's rbp it had itself overwritten, and no stack size
 * or guard page repairs a missing frame. Here the image's `ret` lands on
 * entry_frame, a real C function with a prologue, so the rbp chain the emitted
 * code saves and restores is a chain that exists. The `volatile` on the
 * function pointer stops the compiler folding the call into a tail jump, which
 * would put the image's `ret` back on the bare thread trampoline. */
static W74Entry *volatile g_fn;
__attribute__((no_sanitize_address, no_sanitize("thread")))
static uint64_t entry_frame(void) { return g_fn(); }

/* ===========================================================================
 * FAULT CONTAINMENT, and why it is a HARNESS duty rather than a convenience.
 *
 * MEASURED, and the measurement is what puts it in this lot. Once the
 * twenty-first member ran, CONTROL 3 -- which deliberately corrupts one byte of
 * .text and then RUNS the result -- took the whole gate down with a SEGV inside
 * control_corruption_is_visible, before the CORPUS_TALLY could be printed. So
 * the gate still died before its final report, on an image it had itself
 * broken: the same failure mode this file was repaired for, one level down.
 *
 * A control that provokes a fault must be able to OBSERVE it. Without
 * containment it observes nothing, because the process is gone: the reader gets
 * a crash and no tally, and cannot tell a gate that FOUND something from a gate
 * that FELL OVER. That is the owner's "detect the tests that crash before their
 * final report" item, met by making the crash survivable and then asserting
 * that it was seen.
 *
 * WHERE THE JUMP TARGETS, and this is the part that is easy to get wrong. The
 * fault happens on the GUARD THREAD, inside the image. A siglongjmp from a
 * handler to a sigsetjmp saved on ANOTHER thread's stack is undefined, so the
 * setjmp buffer is saved and jumped within the SAME thread that runs the image:
 * in `guard_thread` below, and in `run_direct` on this thread. The buffer is
 * one global because only one image runs at a time -- pthread_join completes
 * before the next member is entered.
 *
 * MEASURED under this exact ASan+UBSan build, because an assumption here would
 * be worthless: a sigaction handler installed after startup DOES contain a
 * SEGV raised by instrumented code, and execution continues at the setjmp.
 * Verified on a throwaway binary before this was wired in.
 *
 * IT REPORTS, IT DOES NOT SWALLOW. `g_faulted` and `g_fault_sig` become a NOTE
 * ON THE ROW in load_and_run, so a faulted image is a measured outcome this
 * gate prints -- never an absence of one, and never a silent pass. An unarmed
 * fault still _exits: containment is never a licence to ignore a crash that
 * nothing was measuring. */
static sigjmp_buf g_fault_jb;
static volatile sig_atomic_t g_fault_armed, g_faulted;
/* How many times the PARENT's containment handler was actually entered, reset
 * around each control that runs an image in-process. This exists so the claim
 * "control N does not deliberately fault" is a COUNT ON THE ROW and not a
 * sentence in a comment: a reader can see whether the containment was needed
 * without taking the classification on trust. The CHILD installs
 * ctl3_child_handler, never this one, so this counter is parent-side by
 * construction -- it is not a total across both processes. */
static volatile sig_atomic_t g_fault_entries;
static volatile sig_atomic_t g_fault_sig;

static void fault_handler(int sig) {
  g_fault_entries++;
  g_faulted = 1;
  if (g_fault_armed) {
    g_fault_armed = 0;
    siglongjmp(g_fault_jb, 1);
  }
  _exit(128 + sig); /* an unarmed fault stays fatal: never ignored */
}

/* Install the handlers. Called on the thread that is ABOUT TO run an image, so
 * the sigsetjmp that follows is on that same thread's stack. */
static void fault_contain_install(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_handler = fault_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_NODEFER;
  sigaction(SIGSEGV, &sa, NULL);
  sigaction(SIGBUS, &sa, NULL);
  sigaction(SIGILL, &sa, NULL);
  sigaction(SIGFPE, &sa, NULL);
  g_faulted = 0;
  g_fault_sig = 0;
}


/* THE CONTAINMENT CAN BE TOLD TO STAND ASIDE, and the only caller that asks is
 * CONTROL 3's forked child. MEASURED, and the measurement is the reason:
 *
 *   -Wall -Wextra -Werror -O1 -g -fsanitize=address,undefined
 *     the handler IS entered (SA_SIGINFO, si_code=2 SEGV_ACCERR), the siglongjmp
 *     DOES happen, and execution DOES resume inside fault_arm -- and then the
 *     process dies: "*** stack smashing detected ***", __stack_chk_fail called
 *     from fault_arm's OWN EPILOGUE (ASan backtrace under handle_abort=1).
 *   the same flags plus -fno-stack-protector
 *     the handler is entered a SECOND time at the SAME faulting instruction --
 *     si_addr 0x7f00000010a7, rip 0x7f0000001004, rsp identical to the first
 *     entry -- with g_fault_armed already 0, so _exit(128+11).
 *
 * Nothing above says the containment is wrong for what it was measured ON. Lot
 * 69 measured it against a fault raised by INSTRUMENTED C, and it contains
 * that. It cannot contain a fault raised by FOREIGN MACHINE CODE that has
 * already built its own frame on the recovery stack, because the kernel builds
 * its signal frame on that same stack. So the boundary that survives a fault you
 * ASKED for is a process, and the fault CONTROL 3 provokes is contained by one.
 * This flag is how the child says so; nothing else in this file sets it. */
static volatile sig_atomic_t g_no_contain;

/* Arm/disarm around the call. Returns 1 the first time through and 0 after a
 * siglongjmp out of a faulting image, so the caller can read the fault as an
 * outcome instead of crashing on it.
 *
 * `g_no_contain` returns 1 WITHOUT installing a handler and WITHOUT arming:
 * the caller is a child process that wants the fault to be observable from
 * outside, and a handler here would take that observation away from it. */
static int fault_arm(void) {
  if (g_no_contain) {
    g_fault_armed = 0;
    return 1;
  }
  fault_contain_install();
  if (sigsetjmp(g_fault_jb, 1) != 0) return 0;
  g_fault_armed = 1;
  return 1;
}
static void fault_disarm(void) { g_fault_armed = 0; }

/* The register probe, and what it is FOR. `g_rbx_destroyed` records whether the
 * callee actually destroyed rbx across this call. It exists so the repair above
 * can be CHECKED rather than believed: a harness that stopped depending on rbx
 * and merely stopped looking would leave every green below meaningless.
 * CONTROL 4 is what tells those two apart. */
static uint64_t g_rbx_before, g_rbx_after;
static int g_rbx_destroyed, g_arg_matched = 1;
__attribute__((no_sanitize_address, no_sanitize("thread")))
static void *guard_thread(void *arg) {
  /* NOTHING of this frame crosses the call into the image except the return
   * value in rax. The record pointer is re-derived from the global AFTER the
   * image returns, so a callee that destroys rbx -- which the C ABI lets it do
   * only when it declares that, and this product declares it in `clobbers` --
   * cannot turn a register into a pointer. */
  uint64_t r = 0;
  if (fault_arm()) {
    __asm__ volatile("movq %%rbx, %0" : "=m"(g_rbx_before) : : "memory");
    r = entry_frame();
    __asm__ volatile("movq %%rbx, %0" : "=m"(g_rbx_after) : : "memory");
    fault_disarm();
    g_rbx_destroyed = (g_rbx_before != g_rbx_after);
  }
  /* Re-derived AFTER the call, and only from the global: a callee that declared
   * `clobbers {rbx}` and destroyed it cannot turn a register into a pointer.
   * `arg` is CHECKED against that global, so a genuinely wrong pointer is
   * reported by CONTROL 4 rather than silently substituted here. */
  g_arg_matched = (arg == g_call_page);
  Call *c = (Call *)g_call_page;
  /* `called` is set even when the image faulted, because the call WAS made and
   * the fault is reported separately as a note on the row by load_and_run. A
   * fault is an outcome to print, not an absence of one. */
  c->result = r;
  c->called = 1;
  return NULL;
}

/* W74_NO_THREAD=1 calls the image DIRECTLY from this frame: no pthread, no
 * guard stack, no trampoline. It was the switch that eliminated the THREAD as
 * the carrier -- the direct path stopped at the same member with the same
 * address -- so it is kept as the second route and not as the first.
 *
 * The old text here claimed the address was "the value the PREVIOUS member
 * returned". That was wrong, and it was wrong in a way that pointed away from
 * the cause: the member faults when it runs ALONE, and 42 is what IT computes.
 * See the resolved state hunt above g_call_page. */
static int no_thread(void) {
  const char *v = getenv("W74_NO_THREAD");
  return v && *v == '1';
}
static uint64_t run_direct(W74Entry *fn) {
  /* The SAME repair as guard_thread, for the same reason and by the same
   * measurement: a pointer held across `fn()` lives in whatever callee-saved
   * register the compiler chose, and the image is free to destroy that
   * register if its own `clobbers` says so. Re-derived after the call. */
  Call *c = (Call *)g_call_page;
  c->fn = fn;
  c->result = 0;
  c->called = 0;
  uint64_t r = 0;
  if (fault_arm()) {
    __asm__ volatile("movq %%rbx, %0" : "=m"(g_rbx_before) : : "memory");
    r = fn();
    __asm__ volatile("movq %%rbx, %0" : "=m"(g_rbx_after) : : "memory");
    fault_disarm();
    g_rbx_destroyed = (g_rbx_before != g_rbx_after);
  }
  c = (Call *)g_call_page;
  c->result = r;
  c->called = 1;
  return c->called ? c->result : 0;
}

static uint64_t run_on_guard_stack(W74Entry *fn, size_t image) {
  if (no_thread()) return run_direct(fn);
  (void)image;
  Call *c = (Call *)g_call_page;
  c->fn = fn;
  g_fn = fn;
  c->result = 0;
  c->called = 0;
  pthread_attr_t attr;
  if (pthread_attr_init(&attr)) return 0;
  /* THE CANDIDATE, ELIMINATED. This mapping used a NULL hint, so the kernel
   * chose the address -- and the image is at the FIXED LOAD_BIAS. Nothing stops
   * a NULL-hint mapping of 8 MiB + 64 KiB from being placed over an image that
   * is already there: MAP_FIXED_NOREPLACE protects the image from a LATER
   * mapping only by luck of the allocator, and the protection is not asked for.
   * A guard page sealed PROT_NONE over the image's pages would turn my own
   * rebase WRITE into the fault -- and the address in that report, 0x2a, was
   * read at the time as "the value the previous member returned". That reading
   * was wrong in the same way as the one below: 0x2a is the faulting member's
   * own arithmetic, carried in rbx (see the resolved state hunt above
   * g_call_page). The pinning is kept because it is independently correct.
   *
   * So the host mappings are PINNED, each at a measured address, and each one
   * asserts it got the address it asked for. Three fixed, mutually distant
   * addresses remove the entire class: nothing in this file can be placed by
   * the kernel anywhere near the image. */
  void *mem = mmap((void *)(uintptr_t)STACK_BIAS, STACK_BYTES + GUARD_BYTES,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  if (mem == MAP_FAILED || (uint64_t)(uintptr_t)mem != STACK_BIAS) {
    pthread_attr_destroy(&attr);
    return 0;
  }
  /* The guard page sits BELOW the stack, and the stack STARTS ABOVE it. The
   * first version handed pthread the whole mapping and sealed its own first
   * 64 KiB, so the very first push of the frame landed in the guard -- and the
   * address in that report, 0x2a, was read at the time as "the previous
   * member's result". That reading was wrong: 0x2a is what the faulting
   * member ITSELF computes, and it survives to this day as the fault address
   * because the real carrier is the body's own rbx (see the resolved state
   * hunt above g_call_page). So: guard at the bottom, stack handed to pthread
   * as the region ABOVE it, growing down. */
  if (mprotect((uint8_t *)mem, GUARD_BYTES, PROT_NONE)) {
    munmap(mem, STACK_BYTES + GUARD_BYTES);
    pthread_attr_destroy(&attr);
    return 0;
  }
  pthread_attr_setstack(&attr, (char *)mem + GUARD_BYTES, STACK_BYTES);
  pthread_t t;
  int rc = pthread_create(&t, &attr, guard_thread, c);
  pthread_attr_destroy(&attr);
  if (rc) {
    munmap(mem, STACK_BYTES + GUARD_BYTES);
    return 0;
  }
  pthread_join(t, NULL);
  munmap(mem, STACK_BYTES + GUARD_BYTES);
  /* Re-derived for the same reason as everywhere else in this file: `c` must
   * never be a value that crossed a call into an image. Here the image ran on
   * the CHILD's stack, so this frame's callee-saved registers were in fact
   * intact -- but "in fact" is not a property to build a gate on, and the
   * re-derivation costs one load. */
  c = (Call *)g_call_page;
  return c->called ? c->result : 0;
}


/* One section row, read from the image's own table. */
typedef struct {
  uint32_t va, vs, raw, rs;
} Row;

/* Resolve an RVA to a file offset, over the same rule nt_pe_inspect's map() uses
 * at pe.c:25-36. Duplicated rather than shared because pe.c's is static and this
 * file must not edit the product to reach it. */
static int rva_to_file(const Row *s, unsigned n, uint32_t rva, size_t *at) {
  for (unsigned j = 0; j < n; j++) {
    if (rva >= s[j].va && rva - s[j].va + 8 <= s[j].vs && rva - s[j].va + 8 <= s[j].rs) {
      *at = (size_t)s[j].raw + (rva - s[j].va);
      return 1;
    }
  }
  return 0;
}

static int load_and_run(const NtArtifact *a, Loaded *out) {
  memset(out, 0, sizeof *out);
  const uint8_t *b = a->pe.bytes;
  size_t n = a->pe.size;
  if (!b || n < 64 || r16(b) != 0x5a4d) {
    snprintf(out->note, sizeof out->note, "no PE image");
    return 0;
  }
  uint32_t nt = r32(b + 60);
  if (nt + 264 > n || r32(b + nt) != 0x4550) {
    snprintf(out->note, sizeof out->note, "no NT header");
    return 0;
  }
  const uint8_t *o = b + nt + 24;
  unsigned count = r16(b + nt + 6);
  size_t table = (size_t)nt + 264;
  if (!count || count > 96 || table + 40 * (size_t)count > n) {
    snprintf(out->note, sizeof out->note, "no section table");
    return 0;
  }
  uint32_t image = r32(o + 56), entry_rva = r32(o + 16);
  uint32_t reloc_rva = r32(o + 152), reloc_size = r32(o + 156);
  uint64_t preferred = r64(o + 24);

  Row rows[96];
  for (unsigned j = 0; j < count; j++) {
    const uint8_t *h = b + table + 40 * j;
    rows[j].vs = r32(h + 8);
    rows[j].va = r32(h + 12);
    rows[j].rs = r32(h + 16);
    rows[j].raw = r32(h + 20);
  }
  /* THE DELTA, and the assertion that it is not zero. Without this line the
   * whole file would be a run in which rebasing is unnecessary, and every green
   * below would be true for a reason that has nothing to do with relocation. */
  uint64_t base = LOAD_BIAS;
  uint64_t delta = base - preferred;
  if (delta == 0) {
    snprintf(out->note, sizeof out->note, "load bias is zero");
    return 0;
  }

  /* The ADDRESS argument is `base`, not NULL. With MAP_FIXED_NOREPLACE a NULL
   * hint is a request for "anywhere the kernel likes" and the fixed-noreplace
   * guard then applies to whatever that turned out to be, so the bias below
   * would be silently ignored and the whole rebase would be a no-op measured
   * against a kernel-chosen address. The check on the next line is what
   * catches that, and it is the reason it is not a bare MAP_FAILED test. */
  void *p = mmap((void *)(uintptr_t)base, (size_t)image, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  if (p == MAP_FAILED || (uint64_t)(uintptr_t)p != base) {
    snprintf(out->note, sizeof out->note, "mmap at the biased base failed");
    if (p != MAP_FAILED) munmap(p, (size_t)image);
    return 0;
  }
  /* STEP 1: lay the sections out by RVA. */
  for (unsigned j = 0; j < count; j++) {
    if (rows[j].va + rows[j].rs > image || (size_t)rows[j].raw + rows[j].rs > n) {
      snprintf(out->note, sizeof out->note, "section out of range");
      munmap(p, (size_t)image);
      return 0;
    }
    memcpy((uint8_t *)p + rows[j].va, b + rows[j].raw, rows[j].rs);
  }
  out->loaded = 1;
  out->base = base;

  /* STEP 2: the rebase. Every DIR64 site the image's own .reloc names, and the
   * count is kept because "rebased" with sites==0 is a claim about nothing. */
  size_t at;
  int reloc_ok = reloc_size && rva_to_file(rows, count, reloc_rva, &at);
  unsigned sites = 0;
  if (reloc_ok) {
    size_t consumed = 0;
    while (consumed + 8 <= reloc_size) {
      uint32_t page = r32(b + at + consumed), block = r32(b + at + consumed + 4);
      if (block < 8 || consumed + block > reloc_size) break;
      for (size_t k = 8; k + 2 <= block; k += 2) {
        uint16_t r = r16(b + at + consumed + k);
        unsigned type = r >> 12, off = r & 4095u;
        if (!type) continue;
        /* Type 10 is IMAGE_REL_BASED_DIR64. Anything else is REFUSED rather
         * than skipped: a silently unhandled relocation type is how an image
         * loads "successfully" and then computes addresses from a stale word. */
        if (type != 10) {
          snprintf(out->note, sizeof out->note, "relocation type %u unhandled", type);
          munmap(p, (size_t)image);
          out->loaded = 0;
          return 0;
        }
        size_t site;
        if (!rva_to_file(rows, count, page + off, &site)) {
          snprintf(out->note, sizeof out->note, "DIR64 site unmappable");
          munmap(p, (size_t)image);
          out->loaded = 0;
          return 0;
        }
        uint64_t v = r64((uint8_t *)p + (page + off)) + delta;
        for (unsigned q = 0; q < 8; q++)
          ((uint8_t *)p + page + off)[q] = (uint8_t)(v >> (q * 8));
        sites++;
      }
      consumed += block;
    }
  }
  out->sites = sites;
  /* The anchor is the FIRST DIR64 site nt_make_pe always emits (ntasm.c:232
   * puts ro_rva at rvas[0]), so a program with no other absolute address still
   * has sites >= 1 and the count below is a real floor, not a coincidence. */
  out->rebased = reloc_ok && sites > 0;

  /* The .data window, read back after the call. Taken from the section table
   * rather than from the artifact, so what is read is what the LOADER mapped. */
  size_t data_off = 0;
  uint32_t data_rva = 0;
  for (unsigned j = 0; j < count; j++)
    if (r32(b + table + 40 * j + 36) == 0xc0000040u) { /* .data */
      data_rva = rows[j].va;
      data_off = 0;
      out->data_size = rows[j].vs < sizeof out->data ? rows[j].vs : sizeof out->data;
      break;
    }

  /* STEP 3: seal and call. The data region stays writable so a program that
   * stores into its own .data can; the rest is PROT_READ|PROT_EXEC. */
  if (mprotect(p, (size_t)image, PROT_READ | PROT_EXEC)) {
    snprintf(out->note, sizeof out->note, "mprotect failed");
    munmap(p, (size_t)image);
    out->loaded = 0;
    return 0;
  }
  if (data_rva && out->data_size) {
    if (mprotect((uint8_t *)p + data_rva, image - data_rva, PROT_READ | PROT_WRITE)) {
      snprintf(out->note, sizeof out->note, "mprotect of .data failed");
      munmap(p, (size_t)image);
      out->loaded = 0;
      return 0;
    }
  }
  if (entry_rva >= image) {
    snprintf(out->note, sizeof out->note, "entry RVA outside the image");
    munmap(p, (size_t)image);
    out->loaded = 0;
    return 0;
  }
  /* THE CALL, ON A GUARD STACK. A framed NTASM body -- and half the corpus is
   * one, measured: static-data, frame-omission, register-width-binding and
   * features-declared all begin with the frame prologue 9c 51 52 -- begins by
   * pushing thirteen registers and rbp below the host's stack pointer. Calling
   * one directly from main() walks off the red zone, and on a sanitizer build
   * it lands on the shadow of a neighbouring frame: the first version of this
   * file did exactly that and crashed with SEGV on a WRITE to 0x2a after
   * frame-omission, which is the address a spilled register lands on rather
   * than a number this file ever computed. The image is fine; the CALLER's
   * stack was too small for it. So the call goes on its own mmap'd stack with
   * a PROT_NONE guard page below it, which is what a real thread gives it. */
  W74Entry *fn = (W74Entry *)((uint8_t *)p + entry_rva);
  out->returned = run_on_guard_stack(fn, (size_t)image);
  out->called = 1;
  /* A FAULT IS REPORTED, NOT ABSORBED. If the image trapped, the call was still
   * made and `called` is true, so the row above would otherwise print
   * `executed=yes` with a result of 0 and say nothing about why. The note makes
   * the fault a named outcome on the row, which is what CONTROL 3 needs to be
   * able to assert anything at all. */
  if (g_faulted)
    snprintf(out->note, sizeof out->note, "image faulted, signal %d",
             (int)g_fault_sig);
  /* Read the .data back out of the mapped image, AFTER the call. */
  if (data_rva && out->data_size)
    memcpy(out->data, (uint8_t *)p + data_rva, out->data_size);
  (void)data_off;
  munmap(p, (size_t)image);
  return 1;
}

/* ===========================================================================
 * THE CORPUS. Read from the tree, not written here as a literal, so a program
 * added to examples/ntasm-v0/ is a program this gate covers -- the property
 * tests_ntasm_x64_lower_nxo_frames.c:125-128 states for its own two members and
 * the reason its predecessor's literal array could not have it.
 * ========================================================================= */
#define EXDIR "examples/ntasm-v0/"

typedef struct {
  char path[256];
  char name[128];
  int has_second;      /* a second source is needed: a library, or an importer */
  char second[256];
  int expect_refused;  /* the negative control: this program MUST be refused */
  const char *why;     /* what the row is for, and what its scope is          */
  int closing;         /* does it cover a requirement the completion doc calls
                          partiel? named here so the count is not rhetorical   */
  uint64_t want;       /* the result, when one is expected                     */
  int has_want;
} Member;

/* The seventeen sources on the tree, MEASURED by the walk below and listed here
 * only to say what each one is FOR. The walk is what decides membership. */
static const Member MEMBERS[] = {
  {EXDIR "c-bootstrap/return42.ntasm", "return42", 0, "", 0,
   "smallest complete program; the raw-entry shortcut", 0, 42, 1},
  {EXDIR "c-bootstrap/return43.ntasm", "return43", 0, "", 0,
   "one value from return42; the oracle for the negative", 0, 43, 1},
  {EXDIR "c-bootstrap/returnmax.ntasm", "returnmax", 0, "", 0,
   "u64max: an immediate is not truncated to 32 bits", 0,
   UINT64_C(18446744073709551615), 1},
  {EXDIR "c-bootstrap/helper-first.ntasm", "helper-first", 0, "", 0,
   "a call to a second function, then arithmetic in the caller", 0, 42, 1},
  {EXDIR "c-bootstrap/static-data.ntasm", "static-data", 0, "", 0,
   "an initialised .rdata datum read through a typed pointer", 0, 42, 1},
  {EXDIR "c-bootstrap/mutable-data.ntasm", "mutable-data", 0, "", 0,
   "a .data datum stored to and loaded back at run time; its RESULT is the "
   "byte in .data, read out of the image", 0, 42, 1},
  {EXDIR "c-bootstrap/comptime-macro.ntasm", "comptime-macro", 0, "", 0,
   "a comptime block and a macro expansion; the metaprogramming path produces "
   "the bytes", 1, 42, 1},
  {EXDIR "c-bootstrap/call-private-stmt.ntasm", "call-private-stmt", 0, "", 0,
   "a private callee called as a statement, result returned", 0, 21, 1},
  {EXDIR "c-bootstrap-multi/app.ntasm", "multi-app-math", 1,
   EXDIR "c-bootstrap-multi/math.ntasm", 0,
   "a two-module program: an imported callee reached by a macro expansion", 1,
   42, 1},
  {EXDIR "c-bootstrap-controlflow/branching-entry.ntasm", "branching-entry", 0,
   "", 0, "an if/else on a literal condition; both arms return", 0, 42, 1},
  {EXDIR "c-bootstrap-controlflow/comparison-condition-refused.ntasm",
   "comparison-condition-refused", 0, "", 0,
   "SPEC-VERSUS-REFERENCE, and the direction that matters. The C REFERENCE "
   "refuses this with 401, and the reason is not the operands: literal_fits "
   "(frontend.c:1324) has no bool case, integer_kind runs NTF_T_U8..NTF_T_I64 "
   "(frontend.c:1321) and NTF_T_BOOL is 9 against NTF_T_I64 8 "
   "(frontend.h:63-77), so a folded comparison fails a range check it has no "
   "case for. The SPECIFICATION is on the product's side: spec/ntasm/ntasm.md:226-231 "
   "requires the condition to be proved bool and the initial profile proves "
   "'the comparisons', unqualified. The product therefore ACCEPTS, and "
   "tests_ntasm_condition_types.c:67 already asserts that it must. "
   "This row therefore no longer asserts a refusal: it asserts what the "
   "recorded decision says the product does. Resolving it by making the "
   "reference accept, or by making the product refuse, is the cheap fix the "
   "README at examples/ntasm-v0/c-bootstrap-controlflow/README.md:174-177 "
   "names as the dangerous one. Expected 42: the condition is the literal "
   "1 < 2, which folds true, exactly as branching-entry's `if true` does.",
   0, 42, 1},
  {EXDIR "c-bootstrap-controlflow/branching-runtime.ntasm", "branching-runtime",
   0, "", 0,
   "A RUN-TIME-COMPUTED condition with two live arms, which is the shape "
   "branching-entry cannot reach: its condition is the literal `if true`, which "
   "the front end folds before lowering, so that member's body arrives with one "
   "return and not two. This row WAS pinned to a refusal, because the product had "
   "no cmp+setcc encoder and x64_lower_novo.nova:4012-4016 records that omission "
   "as deliberate, refused at :4306. THE ENCODER NOW EXISTS: the shape BUILDS, "
   "LINKS and EXECUTES, and this row asserts that. Expected 43: the entry "
   "receives a non-zero @rcx, so `x == 0` is false and the else arm returns. "
   "THIS IS A LANGUAGE WIDENING AND IT IS NOT SELF-EVIDENT: the pin for this "
   "member in nova_corpus_convergence.c still reads expect=REFUSAL with "
   "observed=AS_PINNED, which this run contradicts. Whoever owns that pin "
   "decides whether the widening is intended; this row states what was measured.",
   0, 43, 1},
  {EXDIR "c-bootstrap-multi/app-data-import.ntasm", "app-data-import", 1,
   EXDIR "c-bootstrap-multi/math-data.ntasm", 1,
   "NEGATIVE CONTROL: an imported DATA item, which the C frontend reads as a "
   "function signature and refuses E200", 0, 0, 0},
  {EXDIR "c-bootstrap-multi/math.ntasm", "math-alone", 0, "", 1,
   "a library with no entry: 701 'exported main function is required' is the "
   "correct answer and not a defect, so this row is compiled-but-not-executed "
   "BY CONSTRUCTION", 0, 0, 0},
  {EXDIR "c-bootstrap-multi/math-data.ntasm", "math-data-alone", 0, "", 1,
   "the other library, and the data half of the refused pair: no entry, so no "
   "image and nothing to execute", 0, 0, 0},
  {EXDIR "frame-gate-fixtures/frame-omission.ntasm", "frame-omission", 0, "",
   0, "a mov body the reference FRAMES; the frame prologue is in .text", 0, 42,
   1},
  {EXDIR "frame-gate-fixtures/shortcut-control.ntasm", "shortcut-control", 0,
   "", 0, "the raw-entry shortcut, as the control for the framed member", 0, 42,
   1},
  {EXDIR "frameless-uefi/program.ntasm", "frameless-uefi", 0, "", 1,
   "OPEN, and reported as such: a loop body, a jmp into it and a dead label, "
   "which the C reference REFUSES 400 'return value required' because its "
   "entry ends in a bare `return`. The program is on the tree and does not "
   "assemble, so it is a named gap and NOT coverage", 0, 0, 0},
  {EXDIR "corpus-e2e/features-declared.ntasm", "features-declared", 0, "", 0,
   "NEW, closing A3: the first program in the corpus to declare a `features` "
   "set, which A3 records as ZERO files. The result is the two-bit mask "
   "SUMMED IN THE BODY, not a literal, so the declaration and the answer are "
   "the same fact", 1, 17, 1},
  {EXDIR "corpus-e2e/register-width-binding.ntasm", "register-width-binding", 0,
   "", 0,
   "NEW, closing A3: four call sites over r8, rdi, rcx and rdx, which the "
   "corpus previously used only rcx and rdx for, and which pins the "
   "ms_abi argument registers the emitted calls must use", 1, 42, 1},
  {EXDIR "corpus-e2e/memory-space-user-data.ntasm", "memory-space-user-data", 0,
   "", 0,
   "NEW, closing A3 and A4: a `user`-space load from .rdata and a store to "
   ".data across three sections, so the RESULT is readable out of the mapped "
   "image's .data and not only out of RAX", 1, 42, 1},
};
#define MEMBER_N (sizeof MEMBERS / sizeof MEMBERS[0])

/* What actually HAPPENED to a row, recorded by run_member and read by the
 * tally. Declared as an array of the table's own length rather than as a
 * counter, so a row that is skipped cannot silently leave the count right. */
/* V_FAULTED is its own verdict and not a flavour of "not executed": the call was
 * made and the machine trapped. Folding it into V_LINKED_ONLY would make a
 * trapped image indistinguishable from one that was never called, which is the
 * distinction the owner's per-test status item is asking for. */
typedef enum {
  V_NOT_RUN, V_EXECUTED, V_REFUSED, V_ABSENT, V_LINKED_ONLY, V_FAULTED
} Verdict;
static Verdict VERDICT[64];


/* Walk the corpus directories and collect every .ntasm on the tree. The count
 * is PRINTED, because a census nobody can see is the defect this lot exists to
 * correct: a number asserted in prose is a promise, and this is the reading. */
static int census(char paths[][320], int cap) {
  static const char *DIRS[] = {"c-bootstrap", "c-bootstrap-multi",
                               "c-bootstrap-controlflow", "frame-gate-fixtures",
                               "frameless-uefi", "corpus-e2e"};
  int found = 0;
  for (unsigned d = 0; d < sizeof DIRS / sizeof DIRS[0]; d++) {
    char dirpath[512];
    snprintf(dirpath, sizeof dirpath, "%s%s", EXDIR, DIRS[d]);
    DIR *dir = opendir(dirpath);
    if (!dir) continue;
    struct dirent *e;
    while ((e = readdir(dir))) {
      size_t len = strlen(e->d_name);
      if (len < 6 || strcmp(e->d_name + len - 6, ".ntasm")) continue;
      if (found >= cap) {
        closedir(dir);
        return -1;
      }
      snprintf(paths[found], 320, "%s%s/%s", EXDIR, DIRS[d], e->d_name);
      found++;
    }
    closedir(dir);
  }
  return found;
}

static void hexdump(char *dst, size_t cap, const uint8_t *b, size_t n) {
  size_t at = 0;
  dst[0] = 0;
  for (size_t i = 0; i < n && at + 3 < cap; i++)
    at += (size_t)snprintf(dst + at, cap - at, "%02x", b[i]);
}

/* Drive one member end to end and print its row. The four columns are printed
 * as four fields, and a row that cannot say RESULT does not print `executed`. */
static void run_member(const Member *m, size_t row) {
  VERDICT[row] = V_NOT_RUN;
  cases++;
  size_t na = 0, nb = 0;
  char *sa = loadf(m->path, &na);
  char *sb = NULL;
  if (!sa) {
    printf("CORPUS %-26s compiled=ABSENT linked=- executed=- result=- scope=%s\n",
           m->name, m->why);
    failures++;
    fprintf(stderr, "FAIL %s: source absent from the tree\n", m->path);
    VERDICT[row] = V_ABSENT;
    return;
  }
  NtFInput in[2];
  unsigned count = 1;
  in[0] = (NtFInput){m->path, sa, na};
  if (m->has_second) {
    sb = loadf(m->second, &nb);
    if (!sb) {
      printf("CORPUS %-26s compiled=ABSENT linked=- executed=- result=- scope=%s\n",
             m->name, m->why);
      failures++;
      fprintf(stderr, "FAIL %s: second source absent\n", m->second);
      free(sa);
      VERDICT[row] = V_ABSENT;
      return;
    }
    in[1] = (NtFInput){m->second, sb, nb};
    count = 2;
  }

  NtArtifact art = {0};
  int compiled = nt_compile_many(in, count, &art);
  if (!compiled) {
    /* A refusal is a legitimate verdict for a program that MUST fail, and a
     * defect for one that must not. The two are told apart by a column the
     * caller set, never by the shape of the error. */
    int refused = m->expect_refused;
    printf("CORPUS %-26s compiled=REFUSED code=%u linked=- executed=- "
           "result=- scope=%s\n",
           m->name, art.error.code, m->why);
    checks++;
    if (!refused) {
      failures++;
      fprintf(stderr, "FAIL %s refused %u: %s\n", m->path, art.error.code,
              art.error.message);
    } else {
      printf("CORPUS_CONTROL %-20s refusal_observed=yes code=%u message=%s\n",
             m->name, art.error.code, art.error.message);
    }
    free(sa);
    free(sb);
    free_artifact(&art);
    VERDICT[row] = V_REFUSED;
    return;
  }
  checks++;
  if (m->expect_refused) {
    failures++;
    fprintf(stderr, "FAIL %s compiled but this row is a NEGATIVE CONTROL and "
                    "must be refused\n",
            m->path);
  }
  free(sb);
  free(sa);

  /* LINK. nt_make_pe is the link step: it resolves the imported callee into the
   * image, writes the entry RVA and emits the DIR64 table. An artifact that
   * compiles but does not link has produced no image and cannot be executed. */
  int linked = nt_make_pe(&art);
  if (!linked) {
    printf("CORPUS %-26s compiled=yes linked=REFUSED code=%u executed=- "
           "result=- scope=%s\n",
           m->name, art.error.code, m->why);
    checks++;
    if (!m->expect_refused) {
      failures++;
      fprintf(stderr, "FAIL %s compiled but did not link\n", m->path);
    }
    free_artifact(&art);
    VERDICT[row] = V_LINKED_ONLY;
    return;
  }
  checks++;
  NtPeInfo info = {0};
  NtDiagnostic ie = {0};
  int inspected = nt_pe_inspect(art.pe.bytes, art.pe.size, &info, &ie);
  checks++;
  if (!inspected) {
    failures++;
    fprintf(stderr, "FAIL %s the product's own PE reader rejects its image: "
                    "%s\n",
            m->path, ie.message);
  }

  Loaded L = {0};
  int ran = load_and_run(&art, &L);

  /* THE ROW. `executed` is printed ONLY when the image was loaded away from its
   * preferred base, every DIR64 site was rebased, and the entry was called and
   * returned. Anything less prints what it did instead, so a row can never
   * claim an execution it did not have. */
  if (ran && L.loaded && L.called && L.note[0]) {
    /* A FAULTED IMAGE IS ITS OWN VERDICT, and it is RED. The call was made and
     * the machine trapped, so `executed=yes` with a result of 0 would be a lie
     * about what happened, and printing nothing at all would be the crash this
     * file exists to remove. The row names the signal and the row fails. */
    printf("CORPUS %-26s compiled=yes linked=yes executed=FAULTED result=- "
           "dir64_sites=%u note=%s scope=%s\n",
           m->name, L.sites, L.note, m->why);
    if (!m->expect_refused) {
      failures++;
      fprintf(stderr, "FAIL %s faulted inside the image: %s\n", m->path,
              L.note);
    }
    VERDICT[row] = V_FAULTED;
  } else if (ran && L.loaded && L.called) {
    char hex[160];
    hexdump(hex, sizeof hex, L.data, L.data_size);
    printf("CORPUS %-26s compiled=yes linked=yes executed=yes result=%llu "
           "bias=0x%llx dir64_sites=%u data=%s entry_rva=%u scope=%s%s\n",
           m->name, (unsigned long long)L.returned,
           (unsigned long long)(L.base - UINT64_C(0x140000000)), L.sites,
           L.data_size ? hex : "-", info.entry_rva, m->why,
           m->closing ? " [CLOSES A partiel]" : "");
    checks++;
    VERDICT[row] = V_EXECUTED;
    if (!L.rebased) {
      failures++;
      fprintf(stderr, "FAIL %s executed without rebasing any DIR64 site\n",
              m->path);
    }
    if (m->has_want) {
      checks++;
      if (L.returned != m->want) {
        failures++;
        fprintf(stderr, "FAIL %s returned %llu want %llu\n", m->path,
                (unsigned long long)L.returned, (unsigned long long)m->want);
      }
    }
  } else {
    printf("CORPUS %-26s compiled=yes linked=yes executed=NO result=- "
           "dir64_sites=%u note=%s scope=%s\n",
           m->name, L.sites, L.note[0] ? L.note : "unreachable", m->why);
    if (!m->expect_refused) {
      failures++;
      fprintf(stderr, "FAIL %s linked but did not execute: %s\n", m->path,
              L.note[0] ? L.note : "no note");
    }
    VERDICT[row] = V_LINKED_ONLY;
  }
  free_artifact(&art);
}

/* ===========================================================================
 * THE INSTRUMENT'S ABILITY TO FAIL. Four controls, and none of them is the
 * "expected" column: each perturbs the MACHINE so that a run which could not
 * fail is exposed.
 *
 * A gate that only ever runs the product on good inputs proves that the
 * product did not crash. These four prove it would have noticed.
 * =========================================================================
 *
 * ============================ THE FOUR CONTROLS, CLASSIFIED.
 *
 * Lot 69 added in-process fault containment and a comment recording that it
 * cannot hold a fault raised by FOREIGN machine code. That left the obvious
 * question open: which of these four controls actually provoke a fault, and
 * therefore which ones the process boundary applies to. Naming them here is not
 * documentation for its own sake -- it is the list that says where the boundary
 * goes, and a boundary applied to the one control that happened to surface is a
 * boundary chosen by symptom rather than by kind.
 *
 *   CONTROL 1  control_refusal_is_real
 *              Runs NO IMAGE. Two nt_compile_many calls and nothing else; a
 *              refusal is observed as a non-zero code on an artifact that was
 *              never made into a PE. It cannot fault, because there is no
 *              machine code to fault in. Prints TWO rows.
 *   CONTROL 2  control_rebase_is_load_bearing
 *              Runs ONE IMAGE, IN-PROCESS, on a CORRECT program. It does not
 *              provoke a fault; a fault is one of the things it would DETECT if
 *              the DIR64 rebase were wrong, which is a different direction --
 *              the fault would be a symptom it is looking for, not an event it
 *              asked for. One row.
 *   CONTROL 3  control_corruption_is_visible
 *              THE ONLY CONTROL THAT DELIBERATELY FAULTS. It flips one byte of
 *              .text and then runs the result, on purpose, and accepts either a
 *              trap or a different number. The provoked run is in a CHILD.
 *   CONTROL 4  control_clobber_destruction_is_visible
 *              Runs ONE IMAGE, IN-PROCESS, on a CORRECT program that declares
 *              `clobbers {rax,rbx}`. The register destruction is the OBSERVED
 *              OUTCOME, not a fault; the image returns 99 normally. One row.
 *
 * SO THE BOUNDARY APPLIES TO ONE CONTROL, and it was already there. What was
 * missing is the other half of the sentence: the PARENT was not reading the
 * child's exit status or the signal that killed it. It printed a signal number
 * that the child wrote about ITSELF, and the child's own `_exit(0)` meant
 * waitpid had nothing to say however the image behaved. A self-report is one
 * reading wearing two hats. Both numbers are on the row now, plus whether they
 * agree.
 *
 * AND THE CLASSIFICATION IS COUNTED, NOT ASSERTED. Controls 2 and 4 run in
 * this process with the containment armed, so `containment_entered=` on their
 * rows is the number of times the handler was actually entered during that
 * control's run. A reader who suspects the classification is stale reads a
 * number off the row instead of taking a comment's word for it.
 *
 * WHAT THE IN-PROCESS CONTAINMENT IS STILL FOR, and it is not retired by the
 * above. Lot 69 measured it on a fault raised by INSTRUMENTED C and it holds
 * that. Controls 2 and 4, and every one of the twenty-one members, run their
 * images in this process under exactly that containment, and it is what keeps a
 * member that faults from taking the gate down before the tally. It is the
 * right boundary for those and only those; CONTROL 3 needs a process because
 * its fault comes from code the compiler never saw, and no in-process handler
 * can survive the kernel stacking a signal frame onto a stack the foreign
 * machine code is already standing on.
 * ========================================================================= */

/* CONTROL 1 -- a program that MUST fail. The tree already holds two, and both
 * are in the table above with expect_refused set. This control asserts the
 * REFUSAL is real by checking it carries a non-zero code and no image: a
 * "refusal" that returned 0 with an artifact would be a silent divergence, and
 * this is the check that tells the two apart. */
static void control_refusal_is_real(const NovaHostImage *unused) {
  (void)unused;
  cases++;
  checks++;
  /* A well-formed program, compiled, must NOT be refused. If the compiler
   * refused everything, the two negative controls above would pass for the
   * wrong reason. */
  static const char *good =
      "module ctl.ok\ntarget x86_64-nexora-uefi\nsection .text {\n"
      "export fn main()->u64\neffects {}\nclobbers {rax} {\nreturn 42\n}\n}\n";
  NtFInput in = {"ctl-ok.ntasm", good, strlen(good)};
  NtArtifact a = {0};
  int ok = nt_compile_many(&in, 1, &a);
  checks++;
  if (!ok) {
    failures++;
    fprintf(stderr, "FAIL refusal control: a valid program was refused %u "
                    "%s\n",
            a.error.code, a.error.message);
  }
  printf("CORPUS_CONTROL %-20s valid_program_refused=no code=%u\n", "not-everything",
         a.error.code);
  free_artifact(&a);

  /* And a program that must fail, must fail WITH a code. */
  static const char *bad =
      "module ctl.bad\ntarget x86_64-nexora-uefi\nsection .text {\n"
      "export fn main()->u64\neffects {}\nclobbers {rax} {\n"
      "load rax,[nope]:ptr<user,u64>\nreturn rax\n}\n}\n";
  NtFInput in2 = {"ctl-bad.ntasm", bad, strlen(bad)};
  NtArtifact b = {0};
  int refused = nt_compile_many(&in2, 1, &b);
  checks++;
  if (refused || b.error.code == 0) {
    failures++;
    fprintf(stderr, "FAIL refusal control: an undefined datum compiled with "
                    "code %u\n",
            b.error.code);
  } else {
    printf("CORPUS_CONTROL %-20s undefined_datum_refused=yes code=%u message=%s\n",
           "undefined-datum", b.error.code, b.error.message);
  }
  free_artifact(&b);
}

/* CONTROL 2 -- the load bias must be load-bearing. Load the SAME image twice,
 * once at the biased address and once at the preferred one, and require that
 * the rebase is what makes the biased run correct. A loader that ignored
 * relocations would return the same wrong number twice and this goes red. */
static void control_rebase_is_load_bearing(void) {
  cases++;
  static const char *src =
      "module ctl.rebase\ntarget x86_64-nexora-uefi\n"
      "section .rdata {\ndata answer:u64=42\n}\n"
      "section .text {\nexport fn main()->u64\neffects {reads_mem(user)}\n"
      "clobbers {rax} {\nload rax,[answer]:ptr<user,u64>\nreturn rax\n}\n}\n";
  NtFInput in = {"ctl-rebase.ntasm", src, strlen(src)};
  NtArtifact a = {0};
  if (!nt_compile_many(&in, 1, &a) || !nt_make_pe(&a)) {
    failures++;
    fprintf(stderr, "FAIL rebase control: the control program did not build "
                    "%u %s\n",
            a.error.code, a.error.message);
    free_artifact(&a);
    return;
  }
  /* Reset immediately before the run and read after it, so the number on this
   * row is what THIS control's run needed from the containment and not a total
   * carried over from an earlier member. See the four-control classification
   * above control_refusal_is_real for why this is printed rather than asserted
   * in prose. */
  g_fault_entries = 0;
  Loaded L = {0};
  int ran = load_and_run(&a, &L);
  checks++;
  if (!ran || !L.called) {
    failures++;
    fprintf(stderr, "FAIL rebase control: the biased load did not run (%s)\n",
            L.note);
    free_artifact(&a);
    return;
  }
  /* The program loads a 42 out of .rdata THROUGH AN ABSOLUTE ADDRESS. If the
   * DIR64 had not been rebased, the value read would be 42 read from an
   * address that does not exist in this mapping, and the run would fault or
   * return something else. It returned 42, so the rebase carried it. */
  checks++;
  if (L.returned != 42) {
    failures++;
    fprintf(stderr, "FAIL rebase control: biased load returned %llu want 42\n",
            (unsigned long long)L.returned);
  }
  checks++;
  if (L.sites == 0) {
    failures++;
    fprintf(stderr, "FAIL rebase control: the rebase touched no DIR64 site, so "
                    "it proved nothing\n");
  }
  printf("CORPUS_CONTROL %-20s biased_load_result=%llu dir64_sites=%u "
         "bias=0x%llx load_bearing=yes containment_entered=%d\n",
         "rebase-is-load-bearing", (unsigned long long)L.returned, L.sites,
         (unsigned long long)(L.base - UINT64_C(0x140000000)),
         (int)g_fault_entries);
  free_artifact(&a);
}

/* ===========================================================================
 * CONTROL 3'S CHILD, and the two canaries it answers with.
 *
 * The verdict is a fixed struct written on a pipe, so the control has ONE shape
 * whatever happened in the child: trapped, or ran to completion. There is no
 * third shape in which the control reports nothing, which is the failure mode
 * this exists to remove -- on this tree the previous version's result WAS a
 * signal, and a control whose result is a signal is not a control.
 * ========================================================================= */
#define CTL3_CANARY 0xA5

typedef struct {
  uint64_t returned;
  uint64_t addr;         /* si_addr of the trap, 0 when it ran to completion */
  uint64_t image_bytes;  /* the image's mapped extent, for the in/out test   */
  uint32_t completed;    /* load_and_run RETURNED in the child               */
  uint32_t faulted;      /* the child trapped                                */
  uint32_t signal;
  uint32_t loaded, called;
  uint32_t in_image;     /* the trap landed inside the image's own mapping    */
  uint32_t lo_changed, hi_changed; /* canary bytes that MOVED                */
  uint32_t canary_lo_moved, canary_hi_moved;
  char note[128];
} Ctl3Verdict;

static int g_ctl3_fd = -1;
static uint8_t *g_ctl3_lo, *g_ctl3_hi;
static uint64_t g_ctl3_image_bytes;

/* The canary scan, and it runs INSIDE the child's signal handler, so it does
 * nothing but read memory and count: no allocation, no stdio, nothing that is
 * not already true of a handler. */
static void ctl3_scan_canaries(Ctl3Verdict *v) {
  uint32_t lo = 0, hi = 0;
  for (size_t i = 0; i < 4096; i++) {
    if (g_ctl3_lo[i] != CTL3_CANARY) lo++;
    if (g_ctl3_hi[i] != CTL3_CANARY) hi++;
  }
  v->lo_changed = lo;
  v->hi_changed = hi;
  v->canary_lo_moved = (lo != 0);
  v->canary_hi_moved = (hi != 0);
}

/* THE CHILD'S ANSWER, and WHY IT THEN DIES OF THE SIGNAL INSTEAD OF LEAVING.
 * Reached on the guard thread, inside the image's own frame, with the kernel's
 * signal frame underneath: so it writes to the pipe and leaves. `write` is
 * async-signal-safe; nothing else here is.
 *
 * IT USED TO `_exit(0)`, and that was a REPORT HOLE, not a style choice. With
 * the fault absorbed, the child's exit status was 0 and WTERMSIG was 0 no
 * matter what the image did, so the parent had NOTHING from waitpid to report
 * and the only signal number on the row was the number the child wrote about
 * itself. A self-report is not a second reader: it cannot disagree with the
 * fault it is reporting, so it cannot catch the fault being mis-reported.
 *
 * So the child restores SIG_DFL for that signal and re-raises. The process now
 * dies of the signal the KERNEL names, the parent reads WTERMSIG from waitpid
 * without asking the child, and the row carries BOTH numbers plus whether they
 * agree. Two readings of one fact, deliberately disagreeable. `_exit` after the
 * raise is unreachable in practice and is there so the function has no path
 * that returns into a frame the image has already trashed. */
static void ctl3_child_handler(int sig, siginfo_t *si, void *uc) {
  (void)uc;
  Ctl3Verdict v;
  memset(&v, 0, sizeof v);
  v.faulted = 1;
  v.signal = (uint32_t)sig;
  v.addr = (uint64_t)(uintptr_t)si->si_addr;
  v.image_bytes = g_ctl3_image_bytes;
  v.in_image = (v.addr >= LOAD_BIAS && v.addr < LOAD_BIAS + v.image_bytes);
  ctl3_scan_canaries(&v);
  ssize_t sent = write(g_ctl3_fd, &v, sizeof v);
  (void)sent;
  struct sigaction dfl;
  memset(&dfl, 0, sizeof dfl);
  dfl.sa_handler = SIG_DFL;
  sigemptyset(&dfl.sa_mask);
  sigaction(sig, &dfl, NULL);
  raise(sig);
  _exit(128 + sig);
}


/* CONTROL 3 -- the instrument can fail on a CORRECT program too. Take a good
 * program, corrupt one byte of its .text, and require the harness to notice
 * that the result moved. A harness that would print 42 for a corrupted image
 * is not measuring the image. This is the control the whole file rests on: it
 * is the one that says the RESULT column is read and not assumed. */
static void control_corruption_is_visible(void) {
  cases++;
  /* The program is helper-first's shape, and that is the point: its 42 is
   * `helper()+40` where helper returns 2, so the answer lives in a CALL and an
   * ADD in the emitted text. The first version of this control used
   * `mov rax,7 ; return 0`, and the reference folds `return 0` to the raw-entry
   * shortcut, so the mov was dead and the image returned 0 whatever the .text
   * said -- the control was green for a reason that had nothing to do with the
   * corruption. A corruption control needs a program whose result MOVES. */
  static const char *src =
      "module ctl.corrupt\ntarget x86_64-nexora-uefi\n"
      "section .text {\n"
      "fn helper()->u64\neffects {}\nclobbers {} {\nreturn 2\n}\n"
      "export fn main()->u64\neffects {}\nclobbers {rax} {\n"
      "return helper()+40\n}\n}\n";
  NtFInput in = {"ctl-corrupt.ntasm", src, strlen(src)};
  NtArtifact a = {0};
  if (!nt_compile_many(&in, 1, &a) || !nt_make_pe(&a)) {
    failures++;
    fprintf(stderr, "FAIL corruption control: did not build %u %s\n",
            a.error.code, a.error.message);
    free_artifact(&a);
    return;
  }
  Loaded good = {0};
  int ran_good = load_and_run(&a, &good);
  checks++;
  if (!ran_good || !good.called || good.returned != 42) {
    failures++;
    fprintf(stderr, "FAIL corruption control: the intact image returned %llu "
                    "want 42 (%s)\n",
            (unsigned long long)good.returned, good.note);
    free_artifact(&a);
    return;
  }
  /* Corrupt the FIRST byte of .text in the PE's file image -- an `inc`/`dec`/
   * opcode swap that leaves a valid instruction stream but a different answer.
   * The point is not that the program crashes; it is that the RESULT moves. */
  uint32_t nt = r32(a.pe.bytes + 60);
  size_t table = (size_t)nt + 264;
  (void)r16(a.pe.bytes + nt + 6);
  const uint8_t *text = a.pe.bytes + table;
  size_t text_raw = r32(text + 20);
  uint32_t image = r32(a.pe.bytes + nt + 24 + 56);

  /* CANARY A -- THE HARNESS'S OWN WRITE, MEASURED RATHER THAN ASSUMED. The whole
   * file image is copied, ONE byte is flipped, and the two are compared byte for
   * byte. "It corrupts one byte of .text" is a claim about a memory write, and a
   * claim about a memory write is worth exactly as much as the comparison that
   * backs it: here, one byte, at text_raw, and nothing else. */
  size_t corrupt_bytes = 0, corrupt_at = (size_t)-1;
  uint8_t *pristine = malloc(a.pe.size);
  if (!pristine) {
    failures++;
    fprintf(stderr, "FAIL corruption control: no room to snapshot the file image\n");
    free_artifact(&a);
    return;
  }
  memcpy(pristine, a.pe.bytes, a.pe.size);
  a.pe.bytes[text_raw] = (uint8_t)(a.pe.bytes[text_raw] ^ 0xff);
  for (size_t i = 0; i < a.pe.size; i++) {
    if (pristine[i] == a.pe.bytes[i]) continue;
    if (!corrupt_bytes) corrupt_at = i;
    corrupt_bytes++;
  }
  free(pristine);
  checks++;
  if (corrupt_bytes != 1 || corrupt_at != text_raw) {
    failures++;
    fprintf(stderr,
            "FAIL corruption control: the corruption reached %zu byte(s), the "
            "first at %zu; it must be exactly one, at .text raw offset %zu\n",
            corrupt_bytes, corrupt_at, text_raw);
    free_artifact(&a);
    return;
  }

  /* CANARY B -- A PAGE ON EACH SIDE OF THE IMAGE, FILLED BEFORE AND CHECKED
   * AFTER. The image is mapped at the FIXED LOAD_BIAS, so the page below it and
   * the page above its last page are at fixed addresses too, and both can be
   * written with a byte no instruction stream emits. If the corrupted image
   * reaches outside the mapping it was given, that is what moves. This is the
   * question "did the corruption escape its own target", and it is answered by
   * looking at the memory rather than by reasoning about the instruction stream:
   * objdump on the corrupted bytes is an argument, and this is a measurement. */
  size_t pages = ((size_t)image + 4095) / 4096 * 4096;
  void *lo = mmap((void *)(uintptr_t)(LOAD_BIAS - 4096), 4096,
                  PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  void *hi = mmap((void *)(uintptr_t)(LOAD_BIAS + pages), 4096,
                  PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  int canaries = (lo != MAP_FAILED && (uint64_t)(uintptr_t)lo == LOAD_BIAS - 4096 &&
                  hi != MAP_FAILED &&
                  (uint64_t)(uintptr_t)hi == LOAD_BIAS + pages);
  checks++;
  if (!canaries) {
    failures++;
    fprintf(stderr, "FAIL corruption control: the canary pages around the image "
                    "could not be pinned, so the extent of the corruption would "
                    "be UNMEASURED\n");
    if (lo != MAP_FAILED) munmap(lo, 4096);
    if (hi != MAP_FAILED) munmap(hi, 4096);
    free_artifact(&a);
    return;
  }
  memset(lo, CTL3_CANARY, 4096);
  memset(hi, CTL3_CANARY, 4096);

  /* THE PROVOKED FAULT RUNS IN A CHILD, and the parent prints what became of
   * it. A negative control whose result is a signal is not a control: the reader
   * would get a crash and no verdict, and could not tell a gate that FOUND
   * something from a gate that FELL OVER. The child is asked one question -- what
   * did running the corrupted image do -- and answers it on a pipe in every case:
   * it trapped (which signal, where, and whether the canary pages moved), or it
   * ran to completion (what it returned, and what the row says about it).
   *
   * THE CHILD'S OWN OUTPUT IS CAPTURED, and this is not tidiness. ASan and UBSan
   * are compiled into this binary, so they run in the child too -- and when the
   * child dies of the provoked fault, whatever they had to say dies with it. The
   * parent's own clean exit therefore says NOTHING about the child: it is a
   * different process with its own sanitizer state, and "the gate exited 0" is
   * not "the child was clean". Rather than let that pass unstated, the child's
   * fd 1 and fd 2 are pointed at a pipe the parent drains, and the row reports
   * how many bytes came back and whether either sanitizer named an error. The
   * claim printed is about the CHILD's output, and it is measured from the
   * CHILD. */
  fflush(NULL); /* so the child's copy of the buffer cannot be re-flushed */
  /* Both descriptors start CLOSED, because `pipe(fd) || pipe(cfd)` short-circuits:
   * if the first succeeds and the second fails, a half-open pair is exactly what
   * an uninitialised cfd would be. Initialising to -1 and closing only what was
   * opened is the difference between failing once and failing once per attempt. */
  int fd[2] = {-1, -1}, cfd[2] = {-1, -1};
  if (pipe(fd) || pipe(cfd)) {
    failures++;
    fprintf(stderr, "FAIL corruption control: no pipe to report through\n");
    if (fd[0] >= 0) close(fd[0]);
    if (fd[1] >= 0) close(fd[1]);
    if (cfd[0] >= 0) close(cfd[0]);
    if (cfd[1] >= 0) close(cfd[1]);
    munmap(lo, 4096);
    munmap(hi, 4096);
    free_artifact(&a);
    return;
  }
  pid_t kid = fork();
  if (kid < 0) {
    failures++;
    fprintf(stderr, "FAIL corruption control: fork failed\n");
    close(fd[0]);
    close(fd[1]);
    if (cfd[0] >= 0) close(cfd[0]);
    if (cfd[1] >= 0) close(cfd[1]);
    munmap(lo, 4096);
    munmap(hi, 4096);
    free_artifact(&a);
    return;
  }
  if (kid == 0) {
    if (cfd[1] >= 0) {
      /* After this point the child's failures are its OWN, and are read back
       * below rather than landing on the parent's terminal. */
      dup2(cfd[1], 1);
      dup2(cfd[1], 2);
      close(cfd[0]);
      close(cfd[1]);
    }
    close(fd[0]);
    g_ctl3_lo = (uint8_t *)lo;
    g_ctl3_hi = (uint8_t *)hi;
    g_ctl3_image_bytes = (uint64_t)pages;
    g_ctl3_fd = fd[1];
    g_no_contain = 1;
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = ctl3_child_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    Loaded bad = {0};
    int ran_bad = load_and_run(&a, &bad);
    Ctl3Verdict v = {0};
    v.completed = 1;
    v.loaded = (uint32_t)bad.loaded;
    v.called = (uint32_t)bad.called;
    v.returned = bad.returned;
    memcpy(v.note, bad.note, sizeof v.note);
    ctl3_scan_canaries(&v);
    ssize_t sent = write(fd[1], &v, sizeof v);
    (void)sent;
    _exit(ran_bad ? 0 : 1);
  }
  close(fd[1]);
  if (cfd[1] >= 0) close(cfd[1]);

  /* THE CHILD'S OUTPUT IS DRAINED FIRST, and the order is load-bearing rather
   * than stylistic. The child writes whatever the sanitizers say and then
   * writes its verdict; if the parent waited on the verdict pipe first, a child
   * with enough sanitizer text to fill the output pipe would block on that
   * write while the parent blocked on the verdict pipe, and the two would wait
   * on each other. Draining the output pipe to EOF first cannot deadlock:
   * EOF on it means the child has closed it, which is after every write it was
   * going to make, verdict included. */
  /* ALWAYS DRAINED TO EOF, even when the buffer is full or cannot be grown.
   * The earlier shape of this loop stopped reading at the cap, which left the
   * child blocked on a write to a pipe nobody was draining -- a hang, not a
   * report, and the worst possible failure for an instrument whose whole job is
   * to report what the child did. Bytes past the cap are counted and discarded;
   * only the retained prefix is scanned, and the row says so by printing the
   * RETAINED count next to the TOTAL rather than passing a truncated scan off
   * as a complete one. EINTR is retried rather than mistaken for EOF. */
  size_t kept = 0, total = 0, cbytes, ccap = 8192, ccap_max = 1u << 20;
  char *cbuf = (char *)malloc(ccap);
  for (;;) {
    char scratch[4096];
    char *dst;
    size_t room;
    if (cbuf && kept < ccap) {
      dst = cbuf + kept;
      room = ccap - kept;
    } else {
      dst = scratch;
      room = sizeof scratch;
    }
    ssize_t n = read(cfd[0], dst, room);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) break;
    total += (size_t)n;
    if (cbuf && kept < ccap) {
      size_t fit = (size_t)n;
      if (kept + fit > ccap) fit = ccap - kept;
      kept += fit;
    }
    if (cbuf && kept == ccap && ccap < ccap_max) {
      size_t ncap = ccap * 2 > ccap_max ? ccap_max : ccap * 2;
      char *nb = (char *)realloc(cbuf, ncap);
      if (nb) { cbuf = nb; ccap = ncap; }
    }
  }
  if (cfd[0] >= 0) close(cfd[0]);
  if (cbuf && total > kept) {
    failures++;
    fprintf(stderr, "FAIL corruption control: the child wrote %zu bytes and only "
                    "%zu were retained, so its sanitizer output was TRUNCATED and "
                    "what follows is not a complete reading\n",
            total, kept);
  }
  /* cbytes is the RETAINED PREFIX; `total` is what the child actually wrote. Both
   * go on the row, so "the child was quiet" and "the child's output was cut
   * short" are distinguishable instead of both reading as a small number. */
  cbytes = kept;
  int child_asan = 0, child_ubsan = 0;
  if (cbuf && cbytes) {
    char *z = (char *)malloc(cbytes + 1);
    if (z) {
      memcpy(z, cbuf, cbytes);
      z[cbytes] = 0;
      child_asan = strstr(z, "AddressSanitizer") != NULL ||
                   strstr(z, "LeakSanitizer") != NULL;
      child_ubsan = strstr(z, "runtime error:") != NULL ||
                   strstr(z, "UndefinedBehaviorSanitizer") != NULL;
      free(z);
    }
  }
  free(cbuf);

  Ctl3Verdict v;
  memset(&v, 0, sizeof v);
  size_t got = 0;
  while (got < sizeof v) {
    ssize_t n = read(fd[0], (char *)&v + got, sizeof v - got);
    if (n <= 0) break;
    got += (size_t)n;
  }
  close(fd[0]);
  int status = 0;
  while (waitpid(kid, &status, 0) < 0 && errno == EINTR) {}
  /* THE KERNEL'S VERDICT, ASKED OF NOBODY. The child's own handler said which
   * signal it saw; waitpid says which signal actually killed it. These are two
   * readings of one fact and the row prints both plus whether they agree,
   * because a self-report and an outcome that cannot disagree are one reading
   * wearing two hats. */
  int w_exited = WIFEXITED(status);
  int w_status = w_exited ? WEXITSTATUS(status) : -1;
  int w_signaled = WIFSIGNALED(status);
  int w_sig = w_signaled ? WTERMSIG(status) : 0;
  munmap(lo, 4096);
  munmap(hi, 4096);

  /* THE REPORT EXISTS. Not "the gate finished" -- a verdict, from the child,
   * about what the corrupted image did. Without one there is nothing to assert
   * and the control is decoration. */
  checks++;
  if (got != sizeof v) {
    failures++;
    fprintf(stderr,
            "FAIL corruption control: the child reported %zu of %zu bytes (status "
            "%d%s%d), so the corrupted image left no verdict at all\n",
            got, sizeof v, status, WIFSIGNALED(status) ? " signal " : "",
            WIFSIGNALED(status) ? WTERMSIG(status) : 0);
    free_artifact(&a);
    return;
  }

  /* THE FAULT PATH IS A PASS FOR THIS CONTROL, and it has to be. Corrupting
   * .text can land on a valid-but-different instruction OR on a trap; both
   * prove the RESULT is read off the image, and neither may take the gate down
   * before the tally. What is NOT a pass is a trap whose address is outside the
   * image: that is the corruption escaping the one byte it was aimed at.
   *
   * "FAULTED AS EXPECTED" IS A VERDICT ABOUT FOUR FACTS TOGETHER, and it is
   * narrower than "the child reported a fault". The image faulted; the fault
   * landed inside the image's own mapping; the canary pages on either side did
   * not move; and the kernel killed the child with the SAME signal the child's
   * handler named. Any one of those failing is not the expected fault but a
   * different event, and each is printed as its own field so a reader can see
   * WHICH one broke rather than only that something did. */
  if (v.faulted) {
    checks++;
    if (v.canary_lo_moved || v.canary_hi_moved) {
      failures++;
      fprintf(stderr,
              "FAIL corruption control: the corrupted image WROTE OUTSIDE its "
              "own mapping -- %u byte(s) below, %u above (fault at 0x%llx)\n",
              v.lo_changed, v.hi_changed, (unsigned long long)v.addr);
    } else {
      checks++;
      /* The kernel's verdict must MATCH the child's. A child that says SIGSEGV
       * and then exits 0 has not faulted, it has narrated one; and a child
       * killed by a signal its handler never saw has been killed by something
       * this control did not provoke. Either is a disagreement worth red. */
      int agrees = w_signaled && (unsigned)w_sig == v.signal;
      if (!agrees) {
        failures++;
        fprintf(stderr,
                "FAIL corruption control: the child's handler reported signal %u "
                "but waitpid says exited=%d status=%d signaled=%d sig=%d -- the "
                "two readings of the child's fate do not agree\n",
                v.signal, w_exited, w_status, w_signaled, w_sig);
      }
      checks++;
      if (!v.in_image) {
        failures++;
        fprintf(stderr,
                "FAIL corruption control: the fault address 0x%llx is OUTSIDE the "
                "image's own mapping of %llu bytes, so the corruption escaped the "
                "byte it was aimed at\n",
                (unsigned long long)v.addr, (unsigned long long)v.image_bytes);
      }
      printf("CORPUS_CONTROL %-20s intact=%llu corrupted=- outcome=%s signal=%u "
             "addr=0x%llx inside_image=%s canary_pages_clean=yes "
             "corrupted_bytes=1 at=%zu moved=yes "
             "child_exit=%d child_signal=%d signals_agree=%s "
             "child_output_bytes=%zu child_output_total=%zu child_asan=%s "
             "child_ubsan=%s\n",
             "corruption-is-visible", (unsigned long long)good.returned,
             agrees ? "faulted-as-expected" : "faulted-but-disagreed", v.signal,
             (unsigned long long)v.addr, v.in_image ? "yes" : "NO", text_raw,
             w_status, w_sig, agrees ? "yes" : "NO", cbytes, total,
             child_asan ? "yes" : "no", child_ubsan ? "yes" : "no");
    }
  } else {
    checks++;
    if (v.completed && v.called && v.returned == good.returned) {
      failures++;
      fprintf(stderr, "FAIL corruption control: a corrupted .text returned the "
                      "SAME %llu, so the result is not read off the image\n",
              (unsigned long long)v.returned);
    } else {
      checks++;
      /* The same disagreement check on the other branch. A child that reports
       * "I ran to completion" and was then killed by a signal has been killed
       * by something after its verdict, and a row that printed only the
       * self-report would hide that entirely. */
      if (w_signaled) {
        failures++;
        fprintf(stderr,
                "FAIL corruption control: the child reported that it ran to "
                "completion but was killed by signal %d, so its own verdict and "
                "its fate disagree\n",
                w_sig);
      }
      checks++;
      if (v.canary_lo_moved || v.canary_hi_moved) {
        failures++;
        fprintf(stderr,
                "FAIL corruption control: the corrupted image WROTE OUTSIDE its "
                "own mapping -- %u byte(s) below, %u above\n",
                v.lo_changed, v.hi_changed);
      } else {
        printf("CORPUS_CONTROL %-20s intact=%llu corrupted=%llu outcome=%s "
               "canary_pages_clean=yes corrupted_bytes=1 at=%zu moved=yes "
               "child_exit=%d child_signal=%d "
               "child_output_bytes=%zu child_output_total=%zu child_asan=%s "
               "child_ubsan=%s\n",
               "corruption-is-visible", (unsigned long long)good.returned,
               (unsigned long long)v.returned,
               w_signaled ? "different-result-but-died" : "different-result",
               text_raw, w_status, w_sig, cbytes, total,
               child_asan ? "yes" : "no", child_ubsan ? "yes" : "no");
      }
    }
  }
  free_artifact(&a);
}


/* CONTROL 4 -- THE NEGATIVE CONTROL, and the reason the repair above can be
 * believed. Controls 1-3 all ask "would this instrument notice a broken
 * product?". This one asks the harder question: "if the harness was repaired so
 * it no longer dies, has the REPAIR gone blind?"
 *
 * THE OBVIOUS FALSE POSITIVE IS "the harness stopped crashing". A harness that
 * catches the error instead of dying STILL HAS THE BUG, and a gate that only
 * stopped crashing has proved nothing at all. So this control builds a callee
 * that DECLARES `clobbers {rbx}` -- the exact shape that produced the fault --
 * runs it, and REQUIRES the register probe to observe rbx destroyed. If the
 * repair ever works by ignoring the callee's clobber contract rather than by
 * not depending on it, this goes red.
 *
 * IT HAS BEEN PROVEN TO BITE, in the negative and on this tree: a build with
 * the probe's comparison forced to zero -- a deliberately BLIND instrument --
 * produces `failures=1` and `EXIT 1` on the very same control, while the real
 * build produces `rbx_destroyed=yes` and `failures=0`. A control that cannot
 * fail is not a control, and this one was shown failing before it was shown
 * passing. */
static void control_clobber_destruction_is_visible(void) {
  cases++;
  /* The dying member's shape, built inline so the control does not depend on
 * any file being on the tree: `clobbers {rax,rbx}` and a body that leaves a
 * KNOWN value in rbx. */
  static const char *src =
      "module ctl.clobber\n"
      "target x86_64-nexora-uefi\n"
      "section .rdata {\ndata k:u64=99\n}\n"
      "section .text {\n"
      "export fn main()->u64\n"
      "effects {reads_mem(user)}\n"
      "clobbers {rax,rbx} {\n"
      "load rbx,[k]:ptr<user,u64>\n"
      "return rbx\n}\n"
      "}\n";
  NtFInput in = {"ctl-clobber.ntasm", src, strlen(src)};
  NtArtifact a = {0};
  if (!nt_compile_many(&in, 1, &a) || !nt_make_pe(&a)) {
    failures++;
    fprintf(stderr, "FAIL clobber control: the control program did not build "
                    "%u %s\n",
            a.error.code, a.error.message);
    free_artifact(&a);
    return;
  }
  g_rbx_destroyed = 0;
  g_arg_matched = 0;
  g_fault_entries = 0;
  Loaded L = {0};
  int ran = load_and_run(&a, &L);
  checks++;
  if (!ran || !L.called) {
    failures++;
    fprintf(stderr, "FAIL clobber control: the clobbering image did not run "
                    "(%s)\n",
            L.note);
    free_artifact(&a);
    return;
  }
  checks++;
  if (!g_rbx_destroyed) {
    /* THE ASSERTION THAT MATTERS. The instrument claims to observe that a
     * callee declaring `clobbers {rbx}` leaves rbx holding the body's value.
     * If it did NOT observe that, the probe is blind and every green this gate
     * prints about such a callee is worthless. */
    failures++;
    fprintf(stderr, "FAIL clobber control: the image declares clobbers {rbx} "
                    "and the instrument did NOT see rbx change "
                    "(before=%016llx after=%016llx), so the probe is blind\n",
            (unsigned long long)g_rbx_before,
            (unsigned long long)g_rbx_after);
  }
  checks++;
  if (!g_arg_matched) {
    failures++;
    fprintf(stderr, "FAIL clobber control: the thread argument did not match "
                    "the call page, so the record pointer is not the one the "
                    "harness passed\n");
  }
  /* The callee's own arithmetic must have survived as the RESULT even though
 * its register did not: 99 is `k`, loaded into rbx and returned. This is the
 * property the repair must preserve -- not surviving by ignoring the clobber,
 * but by reading the answer out of rax. */
  checks++;
  if (L.returned != 99) {
    failures++;
    fprintf(stderr, "FAIL clobber control: the clobbering image returned %llu "
                    "want 99\n",
            (unsigned long long)L.returned);
  }
  printf("CORPUS_CONTROL %-20s rbx_destroyed=%s arg_matched=%s result=%llu "
         "probe=sees containment_entered=%d\n",
         "clobber-is-visible", g_rbx_destroyed ? "yes" : "NO",
         g_arg_matched ? "yes" : "no", (unsigned long long)L.returned,
         (int)g_fault_entries);
  free_artifact(&a);
}

int main(void) {
  /* The call record's page, allocated once and never on a C stack. See the note
   * above run_on_guard_stack for the measurement that forced it. A page of its
   * own also means the record is not adjacent to anything a frame can spill
   * into, which is the property being bought. */
  g_call_page = mmap((void *)(uintptr_t)CALLPAGE_BIAS, 4096, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
  if (g_call_page == MAP_FAILED || (uint64_t)(uintptr_t)g_call_page != CALLPAGE_BIAS) {
    fprintf(stderr, "FAIL the call record page could not be mapped\n");
    return 1;
  }
  /* THE CENSUS, printed, and compared in BOTH directions against the table
   * above: a source on the tree with no row here is a coverage hole, and a row
   * naming a source that is not on the tree is a claim the tree does not
   * support. The first is the direction the corpus doc says a reader forgets. */
  static char paths[256][320];
  int n = census(paths, 256);
  checks++;
  if (n < 0) {
    failures++;
    fprintf(stderr, "FAIL census: more than 256 sources under %s\n", EXDIR);
    printf("CENSUS sources=? rows=%zu status=overflow\n", MEMBER_N);
    return 1;
  }
  checks++;
  if ((size_t)n != MEMBER_N) {
    failures++;
    fprintf(stderr, "FAIL census: the tree holds %d .ntasm and the table has "
                    "%zu rows\n",
            n, MEMBER_N);
  }
  for (int i = 0; i < n; i++) {
    int found = 0;
    for (size_t j = 0; j < MEMBER_N; j++)
      if (!strcmp(paths[i], MEMBERS[j].path)) found = 1;
    checks++;
    if (!found) {
      failures++;
      fprintf(stderr, "FAIL census: %s is on the tree and has no row\n",
              paths[i]);
    }
  }
  for (size_t j = 0; j < MEMBER_N; j++) {
    FILE *f = fopen(MEMBERS[j].path, "rb");
    checks++;
    if (!f) {
      failures++;
      fprintf(stderr, "FAIL census: row %s names %s, which is absent\n",
              MEMBERS[j].name, MEMBERS[j].path);
    } else {
      fclose(f);
    }
  }
  printf("CENSUS sources=%d rows=%zu status=%s\n", n, MEMBER_N,
         (size_t)n == MEMBER_N ? "closed" : "OPEN");

  for (size_t j = 0; j < MEMBER_N; j++) run_member(&MEMBERS[j], j);

  control_refusal_is_real(NULL);
  control_rebase_is_load_bearing();
  control_corruption_is_visible();
  control_clobber_destruction_is_visible();

  /* The tally is read off what HAPPENED, not off what the table intended. The
   * first version derived all three numbers from the Member struct, which
   * means a row that compiled, linked and executed while its `has_want` said
   * otherwise would have been counted as not executed -- a tally that cannot
   * disagree with the rows above it is not a tally. */
  unsigned closing = 0, executed = 0, refused = 0, absent = 0, unexecuted = 0,
           faulted = 0;
  for (size_t j = 0; j < MEMBER_N; j++) {
    if (MEMBERS[j].closing) closing++;
    switch (VERDICT[j]) {
      case V_EXECUTED: executed++; break;
      case V_REFUSED: refused++; break;
      case V_ABSENT: absent++; break;
      case V_FAULTED: faulted++; break;
      default: unexecuted++; break;
    }
  }
  /* `faulted` is printed as its OWN number and not folded into
   * compiled_but_not_executed, because a member that trapped inside the image
   * and a member that never produced a run are different failures, and a tally
   * that merges them cannot tell a reader which one happened. */
  printf("CORPUS_TALLY sources=%zu executed_with_result=%u refused=%u "
         "absent=%u faulted_in_image=%u compiled_but_not_executed=%u "
         "closes_a_partiel=%u\n",
         MEMBER_N, executed, refused, absent, faulted, unexecuted, closing);
  printf("NTASM_NOVA_CORPUS_E2E checks=%u failures=%u cases=%u\n", checks,
         failures, cases);
  return failures ? 1 : 0;
}
