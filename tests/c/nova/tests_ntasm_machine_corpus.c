/* tests_ntasm_machine_corpus.c -- THE CORPUS, TWO PRODUCERS, ONE VERDICT EACH.
 *
 * WHAT IT MEASURES. Every program of examples/ntasm-v0, alone and in the three
 * linked pairs the corpus is written for, goes through BOTH producers:
 *
 *   the C reference      nt_compile_many + nt_make_pe, and nt_object_compile
 *                        for the per-module object;
 *   the common chain     nt_machine_pe / nt_machine_object + nt_machine_link:
 *                        parse -> expansion -> validation -> NTIR -> Machine IR
 *                        -> machine_emit -> NXO -> link/PE, the production path.
 *
 * Both PE files are LOADED AND CALLED (run_child, a forked child with an alarm)
 * and the two u64 results are compared. The per-module objects are compared
 * symbol by symbol: name, flags, section and contract text, and a data
 * symbol's size. The two sides are built by two different producers in two
 * different languages, so an agreement is a witness and a disagreement is
 * attributed to one of the two producers -- never to this gate, which writes
 * no expected value of its own except the inline refusal rows below.
 *
 * THE VERDICTS. AGREE (both executed, same value), DIVERGE (both executed,
 * different values), C_ONLY / MIR_ONLY (one produced an executable, the other
 * refused), REFUSED_BOTH, FAULT (the chain faulted in the host, or its PE
 * crashed). Every one except AGREE and REFUSED_BOTH is a failure: the corpus is
 * the scope A7 is judged on, and a refusal the reference does not make is a
 * missing feature, not a policy.
 *
 * THE CANARY. The same chain is then built a SECOND time from a copy of the
 * toolchain in which machine_emit.nova's one `add` encoding is replaced by
 * `sub` -- three bytes for three bytes, so nothing else in the module moves --
 * and the corpus is executed again. Programs whose result depends on an
 * addition must change, and programs without one must not. If nothing changes,
 * the executables were not emitted by machine_emit and the corpus verdicts
 * above prove nothing about it (PROOF_INVALID).
 *
 * Banner: NTASM_NOVA_MACHINE_CORPUS checks=N failures=N cases=N plus a TALLY
 * line. Runs from the repository root, as the other machine gates do. */
#define _GNU_SOURCE
#include <dirent.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
static pid_t bounded_fork(void) { pid_t p = fork(); if (p == 0) alarm(5); return p; }
#define fork bounded_fork
#define main existing_pe_execution_gate_main
#include "tests_ntasm_pe_exec.c"
#undef main
#undef fork
#include "../../../compiler/c/nova/backend/machine_driver.h"
#include "../../../compiler/c/ntasm/formats/object.h"
#include "machine_instruction_parity_checks.h"

#define EX "examples/ntasm-v0/"
typedef struct { const char *name, *a, *b; } Case;
static const Case CORPUS[] = {
    {"return42", EX "c-bootstrap/return42.ntasm", NULL},
    {"return43", EX "c-bootstrap/return43.ntasm", NULL},
    {"returnmax", EX "c-bootstrap/returnmax.ntasm", NULL},
    {"helper-first", EX "c-bootstrap/helper-first.ntasm", NULL},
    {"static-data", EX "c-bootstrap/static-data.ntasm", NULL},
    {"mutable-data", EX "c-bootstrap/mutable-data.ntasm", NULL},
    {"comptime-macro", EX "c-bootstrap/comptime-macro.ntasm", NULL},
    {"call-private-stmt", EX "c-bootstrap/call-private-stmt.ntasm", NULL},
    {"branching-entry", EX "c-bootstrap-controlflow/branching-entry.ntasm", NULL},
    {"comparison-condition", EX "c-bootstrap-controlflow/comparison-condition-refused.ntasm", NULL},
    {"branching-runtime", EX "c-bootstrap-controlflow/branching-runtime.ntasm", NULL},
    {"frame-omission", EX "frame-gate-fixtures/frame-omission.ntasm", NULL},
    {"shortcut-control", EX "frame-gate-fixtures/shortcut-control.ntasm", NULL},
    {"frameless-uefi", EX "frameless-uefi/program.ntasm", NULL},
    {"features-declared", EX "corpus-e2e/features-declared.ntasm", NULL},
    {"register-width-binding", EX "corpus-e2e/register-width-binding.ntasm", NULL},
    {"memory-space-user-data", EX "corpus-e2e/memory-space-user-data.ntasm", NULL},
    {"math-alone", EX "c-bootstrap-multi/math.ntasm", NULL},
    {"math-data-alone", EX "c-bootstrap-multi/math-data.ntasm", NULL},
    {"app-alone", EX "c-bootstrap-multi/app.ntasm", NULL},
    {"app-data-import-alone", EX "c-bootstrap-multi/app-data-import.ntasm", NULL},
    {"multi-explicit-app-alone", EX "common-pipeline/multi-explicit-app.ntasm", NULL},
    {"app+math", EX "c-bootstrap-multi/app.ntasm", EX "c-bootstrap-multi/math.ntasm"},
    {"multi-explicit-app+math", EX "common-pipeline/multi-explicit-app.ntasm", EX "c-bootstrap-multi/math.ntasm"},
    {"app-data-import+math-data", EX "c-bootstrap-multi/app-data-import.ntasm", EX "c-bootstrap-multi/math-data.ntasm"},
};
#define CORPUS_N (sizeof CORPUS / sizeof CORPUS[0])

/* Refusals both sides must make, written inline because no corpus file is
 * meant to be refused. They are the same three FAULTS the pipeline gate
 * refuses (an undeclared callee, three operands on cmp, add without
 * changes_flags), on a UEFI module with an exported main; the texts differ
 * from that gate's, so each producer's code is pinned here as measured on 6
 * October 2026 -- C 301/400/501, the chain's validation 310/944/334 -- and a
 * refusal for another reason is red. Two numberings, two validators: which
 * number each prints is a parity question of its own, not an A7 fact. */
typedef struct { const char *name, *text; uint64_t c_code, mir_code; } Inline;
static const Inline REFUSALS[] = {
    /* A6: a stub whose handler is not declared (C 301 "unknown function";
     * stub_table 305 reason 18), and a stub symbol that collides with a
     * declared function (C 300 duplicate; stub_table 305 reason 15). */
    /* A6: the stub C generates declares empty effects and clobbers and the
     * type u64. A handler with effects makes it omit an inferred effect
     * (C 501; the chain's call_effects 325 on the grafted function), and a
     * handler of another result type is refused (C 400; graft 306 reason 15). */
    {"stub-syscall-handler-effects",
     "module a6probe\ntarget x86_64-nexora-uefi\nstub_table t kind syscall {\nstub 0 {\n"
     "handler dispatch\nentry_abi nx64-abi-v0\nexit_abi nx64-abi-v0\nexit return\n"
     "frame syscall.frame\nbindings {}\nhardware_error_code false\nsave {}\nclobbers {}\n"
     "stack_align 16\nswapgs never\ninterrupts preserve\nsection .text\nvisibility export\n"
     "symbol entry0\n}\n}\nsection .text {\nexport fn main()->u64\neffects {}\nclobbers {} {\n"
     "return entry0()\n}\nfn dispatch()->u64\neffects {changes_flags}\nclobbers {} {\n"
     "return 23063\n}\nfn other()->u64\neffects {}\nclobbers {} {\nreturn 7\n}\n}\n",
     501, 325},
    {"stub-syscall-handler-u32",
     "module a6probe\ntarget x86_64-nexora-uefi\nstub_table t kind syscall {\nstub 0 {\n"
     "handler dispatch\nentry_abi nx64-abi-v0\nexit_abi nx64-abi-v0\nexit return\n"
     "frame syscall.frame\nbindings {}\nhardware_error_code false\nsave {}\nclobbers {}\n"
     "stack_align 16\nswapgs never\ninterrupts preserve\nsection .text\nvisibility export\n"
     "symbol entry0\n}\n}\nsection .text {\nexport fn main()->u64\neffects {}\nclobbers {} {\n"
     "return entry0()\n}\nfn dispatch()->u32\neffects {}\nclobbers {} {\nreturn 23063\n}\n"
     "fn other()->u64\neffects {}\nclobbers {} {\nreturn 7\n}\n}\n",
     400, 306},
    {"stub-syscall-ghost",
     "module a6probe\ntarget x86_64-nexora-uefi\nstub_table t kind syscall {\nstub 0 {\n"
     "handler ghost\nentry_abi nx64-abi-v0\nexit_abi nx64-abi-v0\nexit return\n"
     "frame syscall.frame\nbindings {}\nhardware_error_code false\nsave {}\nclobbers {}\n"
     "stack_align 16\nswapgs never\ninterrupts preserve\nsection .text\nvisibility export\n"
     "symbol entry0\n}\n}\nsection .text {\nexport fn main()->u64\neffects {}\nclobbers {} {\n"
     "return entry0()\n}\nfn dispatch()->u64\neffects {}\nclobbers {} {\nreturn 23063\n}\n"
     "fn other()->u64\neffects {}\nclobbers {} {\nreturn 7\n}\n}\n",
     301, 305},
    {"stub-syscall-collision",
     "module a6probe\ntarget x86_64-nexora-uefi\nstub_table t kind syscall {\nstub 0 {\n"
     "handler dispatch\nentry_abi nx64-abi-v0\nexit_abi nx64-abi-v0\nexit return\n"
     "frame syscall.frame\nbindings {}\nhardware_error_code false\nsave {}\nclobbers {}\n"
     "stack_align 16\nswapgs never\ninterrupts preserve\nsection .text\nvisibility export\n"
     "symbol entry0\n}\n}\nsection .text {\nexport fn main()->u64\neffects {}\nclobbers {} {\n"
     "return entry0()\n}\nfn dispatch()->u64\neffects {}\nclobbers {} {\nreturn 23063\n}\n"
     "fn entry0()->u64\neffects {}\nclobbers {} {\nreturn 7\n}\n}\n",
     300, 305},
    {"flags-clobbered-call-undefined",
     "module j.flags_set\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "fn g()->u64\neffects {changes_flags}\nclobbers {rax,rcx,rflags} {\nmov rcx,0\nsub rcx,1\nreturn 7\n}\n"
     "export fn main()->u64\neffects {changes_flags}\nclobbers {rax,rcx,rflags} {\n"
     "mov rcx,0\ncmp rcx,0\ncall g()\nje zero\nreturn 42\nzero:\nreturn 1\n}\n}\n",503,940},

    {"undeclared-callee",
     "module m\ntarget x86_64-nexora-uefi\nsection .text {\nexport fn main()->u64\n"
     "effects {}\nclobbers {} {\ncall helper()\nreturn 0\n}\n}\n", 301, 310},
    {"three-operand-cmp",
     "module m\ntarget x86_64-nexora-uefi\nsection .text {\nexport fn main()->u64\n"
     "effects {changes_flags}\nclobbers {rax,rbx,rcx} {\ncmp rax, rbx, rcx\nreturn 0\n}\n}\n", 400, 944},
    {"undeclared-flags",
     "module m\ntarget x86_64-nexora-uefi\nsection .text {\nexport fn main()->u64\n"
     "effects {}\nclobbers {rax} {\nadd rax, 1\nreturn rax\n}\n}\n", 501, 334},
    /* Fourth review, 7 October 2026: the Nova validation accepts a load wider
     * than the element it reads, which the reference refuses (E400), and the
     * chain then read eight bytes of a one-byte datum. The emitter refuses it
     * (981) until the validation does. */
    {"load-wider-than-element",
     "module m\ntarget x86_64-nexora-uefi\nsection .data {\n    data b:u8=3\n}\nsection .text {\n"
     "export fn main()->u64\neffects {reads_mem(user)}\nclobbers {rax} {\n"
     "load rax,[b]:ptr<user,u8>\nreturn rax\n}\n}\n", 400, 981},
    /* Fifth review, 7 October 2026, the same family: forms the reference
     * refuses (E400) and the chain built. The two-operand `idiv` ran as an
     * UNSIGNED division (machine_ir maps `div` and `idiv` to one OP_DIV and the
     * emitter took the signedness from the operand), and the store wrote eight
     * bytes into a four-byte datum. */
    {"idiv-two-operands",
     "module m\ntarget x86_64-nexora-uefi\nsection .text {\nexport fn main()->u64\n"
     "effects {changes_flags}\nclobbers {rax,rcx,rdx,rflags} {\n"
     "mov rax,0\nsub rax,8\nmov rcx,2\nmov rdx,0\nidiv rax,rcx\nreturn rax\n}\n}\n", 400, 981},
    {"div-two-operands",
     "module m\ntarget x86_64-nexora-uefi\nsection .text {\nexport fn main()->u64\n"
     "effects {changes_flags}\nclobbers {rax,rcx,rdx,rflags} {\n"
     "mov rax,0\nsub rax,8\nmov rcx,2\nmov rdx,0\ndiv rax,rcx\nreturn rax\n}\n}\n", 400, 981},
    {"store-wider-than-element",
     "module m\ntarget x86_64-nexora-uefi\nsection .data {\n    data b:u32=0\n    data c:u32=5\n}\n"
     "section .text {\nexport fn main()->u64\neffects {reads_mem(user),writes_mem(user)}\n"
     "clobbers {rax} {\nmov rax,4294967298\nstore [b]:ptr<user,u32>,rax\nmov rax,0\nreturn rax\n}\n}\n",
     400, 981},
};
#define REFUSALS_N (sizeof REFUSALS / sizeof REFUSALS[0])

/* The 17 historical JOIN rows remain positive execution requirements.
 * Additional rows exercise slices, IN vs OUT/INOUT, preservation, call effects
 * and flags across labels or zero-count shifts. Every positive must execute
 * and agree with the independent C reference; no refusal counts as support. */
typedef struct { const char *name, *text; uint64_t stage, code; } Join;
static const Join JOINS[] = {
    {"flags-across-label-and-mov",
     "module j.flags_label\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "export fn main()->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\n"
     "mov rax,0\ncmp rax,0\ncheckpoint:\nmov rax,5\nje zero\nreturn 1\nzero:\nreturn 42\n}\n}\n",0,0},
    {"zero-shift-preserves-flags",
     "module j.shift_flags\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "export fn main()->u64\neffects {changes_flags}\nclobbers {rax,rcx,rflags} {\n"
     "mov eax,0\ncmp eax,0\nshl eax,0\nje zero\nreturn 1\nzero:\nreturn 42\n}\n}\n",0,0},
    {"out-byte-preserves-family",
     "module j.out_byte\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "fn g(out y:u8 @cl)->u64\neffects {}\nclobbers {rax} {\nmov cl,9\nreturn 0\n}\n"
     "export fn main()->u64\neffects {}\nclobbers {rax,rcx} {\nmov rcx,0x1122334455667700\ncall g()\nreturn rcx\n}\n}\n",0,0},
    {"in-byte-snapshot",
     "module j.in_byte\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "fn g(in y:u8 @cl)->u8\neffects {}\nclobbers {rax,rcx} {\nmov rcx,9\nreturn y\n}\n"
     "export fn main()->u64\neffects {}\nclobbers {rax,rcx} {\ncall g(37)\nreturn rax\n}\n}\n",0,0},
    {"out-high-byte",
     "module j.out_high\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "fn g(out y:u8 @ch)->u64\neffects {}\nclobbers {rax} {\nmov ch,86\nreturn 0\n}\n"
     "export fn main()->u64\neffects {}\nclobbers {rax,rcx} {\nmov rcx,4660\ncall g()\nreturn rcx\n}\n}\n",0,0},
    {"out-name-current-cell",
     "module j.out_name\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "fn g(out y:u64 @rcx)->u64\neffects {}\nclobbers {rax} {\nmov rcx,9\nreturn y\n}\n"
     "export fn main()->u64\neffects {}\nclobbers {rax,rcx} {\ncall g()\nreturn rcx\n}\n}\n",0,0},
    {"inout-name-current-cell",
     "module j.inout_name\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "fn g(inout y:u64 @rcx)->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\nadd rcx,8\nreturn y\n}\n"
     "export fn main()->u64\neffects {changes_flags}\nclobbers {rax,rcx,rflags} {\ncall g(1)\nreturn rcx\n}\n}\n",0,0},
    {"high-byte-write",
     "module j.high_byte\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "export fn main()->u64\neffects {}\nclobbers {rax} {\n"
     "mov rax,4660\nmov ah,86\nreturn rax\n}\n}\n",0,0},
    {"word-write",
     "module j.word\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "export fn main()->u64\neffects {}\nclobbers {rax} {\n"
     "mov rax,1311768467463790320\nmov ax,4660\nreturn rax\n}\n}\n",0,0},
    {"param-name-after-call",
     "module j.param_name\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "fn g()->u64\neffects {}\nclobbers {rax,rcx} {\nmov rcx,9\nreturn 1\n}\n"
     "export fn main(in x:u64 @rcx)->u64\neffects {}\nclobbers {rax,rcx} {\n"
     "call g()\nreturn x\n}\n}\n",0,0},
    {"register-preserved-call",
     "module j.keep\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "fn g()->u64\neffects {}\nclobbers {rax} {\nreturn 1\n}\n"
     "export fn main()->u64\neffects {}\nclobbers {rax,rcx} {\n"
     "mov rcx,37\ncall g()\nreturn rcx\n}\n}\n",0,0},
    {"flags-preserved-call",
     "module j.flags_keep\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "fn g()->u64\neffects {}\nclobbers {rax} {\nreturn 7\n}\n"
     "export fn main()->u64\neffects {changes_flags}\nclobbers {rax,rcx,rflags} {\n"
     "mov rcx,0\ncmp rcx,0\ncall g()\nje zero\nreturn 1\nzero:\nreturn 42\n}\n}\n",0,0},
    {"flags-clobbered-call-fresh-cmp",
     "module j.flags_set\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "fn g()->u64\neffects {changes_flags}\nclobbers {rax,rcx,rflags} {\nmov rcx,0\nsub rcx,1\nreturn 7\n}\n"
     "export fn main()->u64\neffects {changes_flags}\nclobbers {rax,rcx,rflags} {\n"
     "mov rcx,0\ncmp rcx,0\ncall g()\ncmp rcx,0\nje zero\nreturn 42\nzero:\nreturn 1\n}\n}\n",0,0},
    {"read-after-if",
     "module j.read_after_if\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "export fn main(in w:u64 @rcx)->u64\neffects {}\nclobbers {rax,rsi} {\n"
     "if w>0 {\nmov rsi,2\n}\nelse {\nmov rsi,3\n}\nreturn rsi\n}\n}\n", 0, 0},
    {"read-after-label",
     "module j.read_after_label\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "export fn main(in x:u64 @rcx)->u64\neffects {changes_flags}\nclobbers {rax,rflags} {\n"
     "mov rax,7\ncmp rcx,0\njne skip\nmov rax,1\nskip:\nreturn rax\n}\n}\n", 0, 0},
    {"loop-no-compare",
     "module j.loop\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "export fn main()->u64\neffects {changes_flags}\nclobbers {rax,rcx,rflags} {\n"
     "mov rax,0\nmov rcx,4\ntop:\nadd rax,10\nsub rcx,1\njne top\nreturn rax\n}\n}\n", 0, 0},
    {"loop-compare",
     "module j.loop_compare\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "export fn main()->u64\neffects {changes_flags}\nclobbers {rax,rcx,rflags} {\n"
     "mov rax,0\nmov rcx,4\ntop:\nadd rax,10\nsub rcx,1\ncmp rcx,0\njne top\nreturn rax\n}\n}\n", 0, 0},
    {"flags-between",
     "module j.flags_between\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "export fn main(in x:u64 @rcx)->u64\neffects {changes_flags}\nclobbers {rax,rcx,rflags} {\n"
     "cmp rcx,0\nsub rcx,1\nje zero\nreturn 43\nzero:\nreturn 42\n}\n}\n", 0, 0},
    {"memory-destination",
     "module j.memory_destination\ntarget x86_64-nexora-uefi\nsection .data {\n"
     "    data counter:u64=40\n}\nsection .text {\nexport fn main()->u64\n"
     "effects {reads_mem(user),writes_mem(user),changes_flags}\nclobbers {rax,rflags} {\n"
     "add [counter]:ptr<user,u64>,2\nload rax,[counter]:ptr<user,u64>\nreturn rax\n}\n}\n", 0, 0},
    {"alias",
     "module j.alias\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "export fn main()->u64\neffects {}\nclobbers {rax} {\n"
     "mov rax,4660\nmov al,0\nreturn rax\n}\n}\n", 0, 0},
    {"narrow",
     "module j.narrow\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "export fn main()->u32\neffects {changes_flags}\nclobbers {rax,rflags} {\n"
     "mov eax,4294967295\nadd eax,1\nshr eax,1\nreturn eax\n}\n}\n", 0, 0},
    /* The same fault one level up, found while fixing the two above: machine_ir
     * types `200+100` by its left literal (8 bits) and extends that to the
     * declared u64, so it executed as 44 for the reference's 300; `0-8` into an
     * i32 executed as 248 and took the wrong branch of `a/2<0`. */
    {"literal-sum",
     "module j.literal_sum\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "export fn main()->u64\neffects {}\nclobbers {rax} {\n"
     "let a:u64=200+100\nreturn a\n}\n}\n", 0, 0},
    {"signed-division",
     "module j.signed_division\ntarget x86_64-nexora-uefi\nsection .text {\n"
     "export fn main()->u64\neffects {}\nclobbers {rax} {\n"
     "let a:i32=0-8\nlet b:i32=a/2\nif b<0 {\nreturn 1\n}\nreturn 2\n}\n}\n", 0, 0},
    /* Third review, 7 October 2026, all five EXECUTED wrong by the reviewer:
     * a `load` into a sub-register wrote only its own spelling's cell (it has
     * no value of its own, so the destination-width refusal did not reach it),
     * and a register read after a call read the value from BEFORE the call --
     * machine_ir's call writes no cell and clobbers none. */
    {"load-alias-32",
     "module j.load_alias_32\ntarget x86_64-nexora-uefi\nsection .data {\n    data v:u32=7\n}\n"
     "section .text {\nexport fn main()->u64\neffects {reads_mem(user)}\nclobbers {rax} {\n"
     "mov rax,1311768467463790320\nload eax,[v]:ptr<user,u32>\nreturn rax\n}\n}\n", 0, 0},
    {"load-alias-8",
     "module j.load_alias_8\ntarget x86_64-nexora-uefi\nsection .data {\n    data b:u8=0\n}\n"
     "section .text {\nexport fn main()->u64\neffects {reads_mem(user)}\nclobbers {rax} {\n"
     "mov rax,4660\nload al,[b]:ptr<user,u8>\nreturn rax\n}\n}\n", 0, 0},
    {"load-cl-shift",
     "module j.load_cl_shift\ntarget x86_64-nexora-uefi\nsection .data {\n    data b:u8=3\n}\n"
     "section .text {\nexport fn main()->u64\neffects {reads_mem(user),changes_flags}\n"
     "clobbers {rax,rcx,rflags} {\nload cl,[b]:ptr<user,u8>\nmov rcx,1\nmov rax,1\nshl rax,cl\n"
     "return rax\n}\n}\n", 0, 0},
    {"rax-after-call",
     "module j.rax_after_call\ntarget x86_64-nexora-uefi\nsection .text {\nfn f()->u64\n"
     "effects {}\nclobbers {rax} {\nreturn 42\n}\nexport fn main()->u64\neffects {}\n"
     "clobbers {rax} {\nmov rax,5\ncall f()\nreturn rax\n}\n}\n", 0, 0},
    {"rcx-after-call",
     "module j.rcx_after_call\ntarget x86_64-nexora-uefi\nsection .text {\nfn g()->u64\n"
     "effects {}\nclobbers {rax,rcx} {\nmov rcx,9\nreturn 1\n}\nexport fn main()->u64\n"
     "effects {}\nclobbers {rax,rcx} {\nmov rcx,5\ncall g()\nreturn rcx\n}\n}\n", 0, 0},
    /* Fourth review, 7 October 2026, executed wrong (1 for the reference's 9):
     * machine_ir points a bound register's cell at the PARAMETER's value, so
     * `rcx` read after a call that writes rcx is the parameter again, in the
     * call's block and across blocks alike. */
    {"param-register-after-call",
     "module j.param_register_after_call\ntarget x86_64-nexora-uefi\nsection .text {\nfn g()->u64\n"
     "effects {}\nclobbers {rax,rcx} {\nmov rcx,9\nreturn 1\n}\nexport fn main(in x:u64 @rcx)->u64\n"
     "effects {}\nclobbers {rax,rcx} {\ncall g()\nreturn rcx\n}\n}\n", 0, 0},
    {"param-register-after-call-branch",
     "module j.param_register_after_call_branch\ntarget x86_64-nexora-uefi\nsection .text {\nfn g()->u64\n"
     "effects {}\nclobbers {rax,rcx} {\nmov rcx,9\nreturn 1\n}\nexport fn main(in x:u64 @rcx)->u64\n"
     "effects {}\nclobbers {rax,rcx} {\ncall g()\nif x>0 {\nreturn rcx\n}\nreturn 7\n}\n}\n", 0, 0},
    /* A6, 13 October 2026: a safe-return syscall stub table, compiled by the
     * reference from the DECLARATION and by the chain after stub_table.desugar.
     * The mutant binds another handler and must return its value (7), so the
     * binding is what decides the result. Two sections around a .data, and
     * two tables of several entries out of key order, check that the grafted
     * functions land in the right section and bind the right handlers. (An
     * interrupt table is refused by the chain, 306 reason 11, and has no row
     * here: a JOIN requires agreement; that path is proved by stub_table and
     * QEMU.) */
    {"stub-syscall-handler",
     "module a6probe\ntarget x86_64-nexora-uefi\nstub_table t kind syscall {\nstub 0 {\n"
     "handler dispatch\nentry_abi nx64-abi-v0\nexit_abi nx64-abi-v0\nexit return\n"
     "frame syscall.frame\nbindings {}\nhardware_error_code false\nsave {}\nclobbers {}\n"
     "stack_align 16\nswapgs never\ninterrupts preserve\nsection .text\nvisibility export\n"
     "symbol entry0\n}\n}\nsection .text {\nexport fn main()->u64\neffects {}\nclobbers {} {\n"
     "return entry0()\n}\nfn dispatch()->u64\neffects {}\nclobbers {} {\nreturn 23063\n}\n"
     "fn other()->u64\neffects {}\nclobbers {} {\nreturn 7\n}\n}\n", 0, 0},
    {"stub-syscall-multisection",
     "module a6multi\ntarget x86_64-nexora-uefi\nstub_table t kind syscall {\nstub 0 {\n"
     "handler h0\nentry_abi nx64-abi-v0\nexit_abi nx64-abi-v0\nexit return\n"
     "frame syscall.frame\nbindings {}\nhardware_error_code false\nsave {}\nclobbers {}\n"
     "stack_align 16\nswapgs never\ninterrupts preserve\nsection .text\nvisibility export\n"
     "symbol entry0\n}\n}\nsection .text {\nfn h0()->u64\neffects {}\nclobbers {} {\nreturn 11\n"
     "}\nfn h1()->u64\neffects {}\nclobbers {} {\nreturn 13\n}\nfn h2()->u64\neffects {}\n"
     "clobbers {} {\nreturn 17\n}\n}\nsection .data {\ndata cell:u64=5\n}\nsection .text {\n"
     "export fn main()->u64\neffects {}\nclobbers {} {\nreturn entry0()\n}\n}\n", 0, 0},
    {"stub-syscall-two-tables",
     "module a6two\ntarget x86_64-nexora-uefi\nstub_table t kind syscall {\nstub 1 {\n"
     "handler h1\nentry_abi nx64-abi-v0\nexit_abi nx64-abi-v0\nexit return\n"
     "frame syscall.frame\nbindings {}\nhardware_error_code false\nsave {}\nclobbers {}\n"
     "stack_align 16\nswapgs never\ninterrupts preserve\nsection .text\nvisibility export\n"
     "symbol entry1\n}\nstub 0 {\nhandler h0\nentry_abi nx64-abi-v0\nexit_abi nx64-abi-v0\n"
     "exit return\nframe syscall.frame\nbindings {}\nhardware_error_code false\nsave {}\n"
     "clobbers {}\nstack_align 16\nswapgs never\ninterrupts preserve\nsection .text\n"
     "visibility export\nsymbol entry0\n}\n}\nstub_table u kind syscall {\nstub 0 {\n"
     "handler h2\nentry_abi nx64-abi-v0\nexit_abi nx64-abi-v0\nexit return\n"
     "frame syscall.frame\nbindings {}\nhardware_error_code false\nsave {}\nclobbers {}\n"
     "stack_align 16\nswapgs never\ninterrupts preserve\nsection .text\nvisibility export\n"
     "symbol entry2\n}\n}\nsection .text {\nfn h0()->u64\neffects {}\nclobbers {} {\nreturn 11\n"
     "}\nfn h1()->u64\neffects {}\nclobbers {} {\nreturn 13\n}\nfn h2()->u64\neffects {}\n"
     "clobbers {} {\nreturn 17\n}\nexport fn main()->u64\neffects {}\nclobbers {} {\n"
     "let a:u64=entry0()\nlet b:u64=entry1()\nlet c:u64=entry2()\nreturn a*10000+b*100+c\n}\n}\n", 0, 0},
    {"stub-syscall-mutant",
     "module a6probe\ntarget x86_64-nexora-uefi\nstub_table t kind syscall {\nstub 0 {\n"
     "handler other\nentry_abi nx64-abi-v0\nexit_abi nx64-abi-v0\nexit return\n"
     "frame syscall.frame\nbindings {}\nhardware_error_code false\nsave {}\nclobbers {}\n"
     "stack_align 16\nswapgs never\ninterrupts preserve\nsection .text\nvisibility export\n"
     "symbol entry0\n}\n}\nsection .text {\nexport fn main()->u64\neffects {}\nclobbers {} {\n"
     "return entry0()\n}\nfn dispatch()->u64\neffects {}\nclobbers {} {\nreturn 23063\n}\n"
     "fn other()->u64\neffects {}\nclobbers {} {\nreturn 7\n}\n}\n", 0, 0},
};
#define JOINS_N (sizeof JOINS / sizeof JOINS[0])

/* THE KNOWN DIVERGENCES, pinned by their full signature and their owner. A
 * row here is still counted and still printed as what it is; it is not a
 * failure only while the chain refuses at EXACTLY this stage with EXACTLY this
 * code. If the cause moves, or the row starts to agree, the gate goes red and
 * the row must be re-measured -- it cannot quietly stop applying.
 *
 * app.ntasm: `macro twice_plus(v) { return add($v,$v); }` names the module's
 * import `add` inside the template. macro_expand.nova refuses that as the
 * capture of a caller symbol (374 reason 1, spec/ntasm/ntasm.md section 13: "La
 * capture d'un symbole du caller est interdite par defaut"); the C reference
 * accepts it. The disagreement is in the MACRO EXPANDER, stage 2, before any
 * Machine IR exists, and common-pipeline/multi-explicit-app.ntasm is the same
 * program written with the call in the caller's own expression, which both
 * producers execute (AGREE above). Measured 6 October 2026. */
typedef struct { const char *name; uint64_t stage, code; const char *owner; } Known;
static const Known KNOWN[] = {
    {"app+math", 2, 374, "macro_expand hygiene, spec section 13"},
};
static const Known KNOWN_OBJECTS[] = {
    {EX "c-bootstrap-multi/app.ntasm", 2, 374, "macro_expand hygiene, spec section 13"},
};
static const Known *known(const Known *table, size_t n, const char *name) {
  for (size_t i = 0; i < n; i++)
    if (!strcmp(table[i].name, name)) return table + i;
  return NULL;
}

/* A6 (13 October 2026): A STUB SYMBOL THE MODULE PUBLISHES. `main` calling
 * the stub in its own module says nothing about what the object exports, so
 * the stub lives in one unit and another imports it: both producers compile
 * and link the pair. `export` must link and return the handler's value on
 * both sides, with the library's symbol table equal to the reference's
 * (compare_objects: name, flags, section, contract); `local` must be refused
 * by both. */
/* A6 (13 October 2026): A NAMED LIMIT, TESTED. The Machine IR does not carry
 * IRETQ, so the common chain refuses a module holding an interrupt stub table
 * (stub_table.graft, 306 reason 11, reported at stage 3) instead of lowering
 * it without its stubs. The reference runs this module; that is printed, and
 * the interrupt path itself is proved on its own route (stub_table.build_pe
 * and QEMU). The day the chain carries interrupt stubs this row turns red and
 * must become a JOIN. */
typedef struct { const char *name, *text; uint64_t stage, code; } ChainRefusal;
static const ChainRefusal CHAIN_REFUSALS[] = {
    {"stub-interrupt-in-chain",
     "module a6probe\ntarget x86_64-nexora-uefi\n"
     "stub_table t kind interrupt {\nstub 6 {\nhandler advance_saved_rip_2\n"
     "entry_abi nx64-interrupt-same-cpl-v0\nexit_abi nx64-iretq-same-cpl-v0\nexit iretq\n"
     "frame x86_64.frame.no_error.same_cpl\nbindings {}\nhardware_error_code false\n"
     "save {rax}\nclobbers {}\nstack_align 0\nswapgs never\ninterrupts preserve\n"
     "section .text\nvisibility export\nsymbol isr6\n}\n}\n"
     "section .text {\nexport fn main()->u64\neffects {}\nclobbers {} {\nreturn 42\n}\n}\n", 3, 306},
};
#define CHAIN_REFUSALS_N (sizeof CHAIN_REFUSALS / sizeof CHAIN_REFUSALS[0])

typedef struct { const char *name, *lib, *app; int linked; } StubPair;
static const StubPair STUB_PAIRS[] = {
    {"stub-pair-export",
     "module a6lib\ntarget x86_64-nexora-uefi\nstub_table t kind syscall {\nstub 0 {\n"
     "handler dispatch\nentry_abi nx64-abi-v0\nexit_abi nx64-abi-v0\nexit return\n"
     "frame syscall.frame\nbindings {}\nhardware_error_code false\nsave {}\nclobbers {}\n"
     "stack_align 16\nswapgs never\ninterrupts preserve\nsection .text\nvisibility export\n"
     "symbol entry0\n}\n}\nsection .text {\nfn dispatch()->u64\neffects {}\nclobbers {} {\n"
     "return 23063\n}\n}\n",
     "module a6app\ntarget x86_64-nexora-uefi\nimport a6lib.entry0 as e0: fn()->u64\n"
     "effects {}\nclobbers {}\nsection .text {\nexport fn main()->u64\neffects {}\n"
     "clobbers {rax} {\nreturn e0()\n}\n}\n", 1},
    {"stub-pair-local",
     "module a6lib\ntarget x86_64-nexora-uefi\nstub_table t kind syscall {\nstub 0 {\n"
     "handler dispatch\nentry_abi nx64-abi-v0\nexit_abi nx64-abi-v0\nexit return\n"
     "frame syscall.frame\nbindings {}\nhardware_error_code false\nsave {}\nclobbers {}\n"
     "stack_align 16\nswapgs never\ninterrupts preserve\nsection .text\nvisibility local\n"
     "symbol entry0\n}\n}\nsection .text {\nfn dispatch()->u64\neffects {}\nclobbers {} {\n"
     "return 23063\n}\n}\n",
     "module a6app\ntarget x86_64-nexora-uefi\nimport a6lib.entry0 as e0: fn()->u64\n"
     "effects {}\nclobbers {}\nsection .text {\nexport fn main()->u64\neffects {}\n"
     "clobbers {rax} {\nreturn e0()\n}\n}\n", 0},
};
#define STUB_PAIRS_N (sizeof STUB_PAIRS / sizeof STUB_PAIRS[0])

typedef struct { int built, ran, crashed; uint64_t value, stage, code, runtime; } Side;

static void run_pe(const NtBuffer *pe, Side *side) {
  char why[200] = {0};
  uint64_t got = 0;
  int rc = run_child(pe->bytes, pe->size, &got, why, sizeof why);
  side->ran = rc == 0;
  side->crashed = rc == 2;
  side->value = got;
}

/* THE REFERENCE, one case. */
static void reference(const NtFInput *in, size_t n, Side *side) {
  NtArtifact art = {0};
  memset(side, 0, sizeof *side);
  if (nt_compile_many(in, n, &art) && nt_make_pe(&art)) {
    side->built = 1;
    run_pe(&art.pe, side);
  } else {
    side->code = art.error.code;
  }
  nt_artifact_free(&art);
}

/* THE COMMON CHAIN, one case: one PE, or one object per module and a link. */
static void chain(NtMachineImage *m, const NtFInput *in, size_t n, Side *side,
                  NtBuffer *keep) {
  NtBuffer out = {0}, objects[2] = {{0}, {0}};
  NtMachineReport r = {0};
  memset(side, 0, sizeof *side);
  int ok = 0;
  if (n == 1) {
    ok = nt_machine_pe(m, in[0].text, in[0].length, &out, &r);
  } else {
    ok = 1;
    for (size_t i = 0; i < n && ok; i++)
      ok = nt_machine_object(m, in[i].text, in[i].length, objects + i, &r);
    if (ok)
      ok = nt_machine_link(m, objects, n, &out, &r);
  }
  side->runtime = r.runtime;
  side->stage = r.stage;
  side->code = r.code;
  if (ok && out.size && r.runtime == 0) {
    side->built = 1;
    run_pe(&out, side);
    if (keep) { *keep = out; out.bytes = NULL; }
  }
  free(out.bytes);
  free(objects[0].bytes);
  free(objects[1].bytes);
}

static const char *verdict(const Side *c, const Side *m) {
  if (m->runtime || (m->built && m->crashed)) return "FAULT";
  if (c->built && m->built) return (c->ran && m->ran && c->value == m->value) ? "AGREE" : "DIVERGE";
  if (c->built) return "C_ONLY";
  if (m->built) return "MIR_ONLY";
  return "REFUSED_BOTH";
}

/* THE OBJECTS, one module: symbol tables compared field by field. */
static int compare_objects(NtMachineImage *m, const char *path, const NtFInput *in) {
  NtObject co = {0}, mo = {0};
  NtDiagnostic ce = {0}, me = {0};
  NtBuffer bytes = {0};
  NtMachineReport r = {0};
  int c_ok = nt_object_compile(in, 1, &co, &ce);
  int m_ok = nt_machine_object(m, in->text, in->length, &bytes, &r) &&
             nt_object_read(bytes.bytes, bytes.size, &mo, &me);
  char diff[300] = "none";
  int match = c_ok && m_ok;
  if (match && co.target != mo.target) { match = 0; snprintf(diff, sizeof diff, "target %u/%u", co.target, mo.target); }
  if (match && co.symbol_count != mo.symbol_count) {
    match = 0;
    snprintf(diff, sizeof diff, "symbol count %zu/%zu", co.symbol_count, mo.symbol_count);
  }
  for (size_t i = 0; match && i < co.symbol_count; i++) {
    const NtObjectSymbol *a = co.symbols + i, *b = mo.symbols + i;
    if (strcmp(a->name, b->name)) { match = 0; snprintf(diff, sizeof diff, "name[%zu] %s/%s", i, a->name, b->name); }
    else if (a->flags != b->flags) { match = 0; snprintf(diff, sizeof diff, "%s flags %u/%u", a->name, a->flags, b->flags); }
    else if (a->section != b->section) { match = 0; snprintf(diff, sizeof diff, "%s section %u/%u", a->name, a->section, b->section); }
    else if (strcmp(a->contract, b->contract)) {
      match = 0;
      snprintf(diff, sizeof diff, "%s contract C=%.110s MIR=%.110s", a->name, a->contract, b->contract);
    } else if ((a->flags & NT_OBJECT_VARIABLE) && !(a->flags & NT_OBJECT_IMPORT) && a->size != b->size) {
      match = 0;
      snprintf(diff, sizeof diff, "%s size %llu/%llu", a->name, (unsigned long long)a->size, (unsigned long long)b->size);
    }
  }
  if (match && co.entry_symbol != mo.entry_symbol) {
    match = 0;
    snprintf(diff, sizeof diff, "entry %u/%u", co.entry_symbol, mo.entry_symbol);
  }
  printf("OBJECT %-48s c=%s mir=%s symbols=%zu/%zu match=%s diff=%s\n", path,
         c_ok ? "ok" : "REFUSE", m_ok ? "ok" : "REFUSE", co.symbol_count,
         mo.symbol_count, match ? "yes" : (c_ok && m_ok ? "NO" : "-"), diff);
  /* Both producers must describe the module the same way; one refusing what
   * the other accepts is the same failure as a different description -- unless
   * it is a pinned known divergence, which must keep its exact signature. */
  const Known *k = known(KNOWN_OBJECTS, sizeof KNOWN_OBJECTS / sizeof KNOWN_OBJECTS[0], path);
  if (k)
    CHECK(c_ok && !m_ok && r.stage == k->stage && r.code == k->code,
          "%s: the known divergence (%s) still has its pinned signature (C=%d MIR=%d stage %llu code %llu)",
          path, k->owner, c_ok, m_ok, (unsigned long long)r.stage, (unsigned long long)r.code);
  else
    CHECK(c_ok == m_ok, "%s: the C object and the Machine IR object are both produced or both refused (C=%d MIR=%d E%u)",
          path, c_ok, m_ok, (unsigned)r.code);
  if (c_ok && m_ok)
    CHECK(match, "%s: the two objects carry the same symbol table (%s)", path, diff);
  nt_object_free(&co);
  nt_object_free(&mo);
  free(bytes.bytes);
  return c_ok && m_ok && match;
}

static int load_case(const Case *c, NtFInput *in, size_t *n, uint8_t **keep) {
  *n = 0;
  const char *paths[2] = {c->a, c->b};
  for (int i = 0; i < 2 && paths[i]; i++) {
    size_t len = 0;
    keep[i] = readall(paths[i], &len);
    if (!keep[i]) return 0;
    in[i] = (NtFInput){paths[i], (const char *)keep[i], len};
    (*n)++;
  }
  return 1;
}

/* ---- the canary tree ------------------------------------------------------ */
static int copy_file(const char *from, const char *to, const char *needle,
                     const char *replacement, int *hits) {
  size_t n = 0;
  uint8_t *b = readall(from, &n);
  if (!b) return 0;
  if (needle) {
    size_t k = strlen(needle);
    for (size_t i = 0; i + k <= n; i++)
      if (!memcmp(b + i, needle, k)) { memcpy(b + i, replacement, k); (*hits)++; i += k - 1; }
  }
  FILE *f = fopen(to, "wb");
  int ok = f && fwrite(b, 1, n, f) == n;
  if (f) fclose(f);
  free(b);
  return ok;
}
static char canary_root[256];
static void remove_canary(void) {
  if (!canary_root[0]) return;
  char path[512];
  snprintf(path, sizeof path, "%s/compiler/nova", canary_root);
  DIR *d = opendir(path);
  if (d) {
    struct dirent *e;
    while ((e = readdir(d))) {
      if (e->d_name[0] == '.') continue;
      char file[1024];
      snprintf(file, sizeof file, "%s/%s", path, e->d_name);
      unlink(file);
    }
    closedir(d);
  }
  rmdir(path);
  snprintf(path, sizeof path, "%s/toolchain", canary_root); rmdir(path);
  snprintf(path, sizeof path, "%s/compiler/c/nova/frontend/nova.h", canary_root); unlink(path);
  snprintf(path, sizeof path, "%s/compiler/c", canary_root); rmdir(path);
  snprintf(path, sizeof path, "%s/bootstrap/quarantine", canary_root); rmdir(path);
  snprintf(path, sizeof path, "%s/bootstrap", canary_root); rmdir(path);
  rmdir(canary_root);
  canary_root[0] = 0;
}
/* The mutated tree: every .nova file of compiler/nova, with the needle below
 * replaced in machine_emit.nova only, and the host marker the root search
 * requires. Answers the number of needle hits, which must be exactly one. */
#define CANARY_NEEDLE "let n:buf<u8>=\"add\"; rr_owned(e,n,0,1,width);"
#define CANARY_SWAP   "let n:buf<u8>=\"sub\"; rr_owned(e,n,0,1,width);"
static int build_canary(void) {
  snprintf(canary_root, sizeof canary_root, "/tmp/ntasm-mir-canary-XXXXXX");
  if (!mkdtemp(canary_root)) { canary_root[0] = 0; return -1; }
  char path[512];
  snprintf(path, sizeof path, "%s/toolchain", canary_root); mkdir(path, 0700);
  snprintf(path, sizeof path, "%s/compiler/nova", canary_root); mkdir(path, 0700);
  snprintf(path, sizeof path, "%s/bootstrap", canary_root); mkdir(path, 0700);
  snprintf(path, sizeof path, "%s/bootstrap/quarantine", canary_root); mkdir(path, 0700);
  snprintf(path, sizeof path, "%s/compiler/c", canary_root); mkdir(path, 0700);
  snprintf(path, sizeof path, "%s/compiler/c/nova/frontend/nova.h", canary_root);
  if (!copy_file("compiler/c/nova/frontend/nova.h", path, NULL, NULL, NULL)) return -1;
  int hits = 0;
  DIR *d = opendir("compiler/nova");
  if (!d) return -1;
  struct dirent *e;
  while ((e = readdir(d))) {
    size_t l = strlen(e->d_name);
    if (l < 6 || strcmp(e->d_name + l - 5, ".nova")) continue;
    char from[512], to[768];
    snprintf(from, sizeof from, "compiler/nova/%s", e->d_name);
    snprintf(to, sizeof to, "%s/compiler/nova/%s", canary_root, e->d_name);
    int mutate = !strcmp(e->d_name, "machine_emit.nova");
    if (!copy_file(from, to, mutate ? CANARY_NEEDLE : NULL, CANARY_SWAP, &hits)) { closedir(d); return -1; }
  }
  closedir(d);
  return hits;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  NtDiagnostic err = {0};
  NtMachineImage *m = nt_machine_open(".", &err);
  CHECK(m != NULL, "the production chain compiles and maps: E%u %s", err.code, err.message);
  if (!m) {
    printf("NTASM_NOVA_MACHINE_CORPUS checks=%u failures=%u cases=0\n", checks, failures);
    return 1;
  }
  unsigned c_accept = 0, m_accept = 0, agree = 0, diverge = 0, c_only = 0, m_only = 0,
           refused = 0, faults = 0;
  uint64_t values[CORPUS_N];
  int executed[CORPUS_N];
  for (size_t i = 0; i < CORPUS_N; i++) {
    NtFInput in[2];
    uint8_t *keep[2] = {NULL, NULL};
    size_t n = 0;
    cases++;
    executed[i] = 0;
    if (!load_case(CORPUS + i, in, &n, keep)) {
      CHECK(0, "%s: corpus file missing", CORPUS[i].name);
      free(keep[0]); free(keep[1]);
      continue;
    }
    Side c, mm;
    reference(in, n, &c);
    chain(m, in, n, &mm, NULL);
    const char *v = verdict(&c, &mm);
    c_accept += c.built;
    m_accept += mm.built;
    if (!strcmp(v, "AGREE")) agree++;
    else if (!strcmp(v, "DIVERGE")) diverge++;
    else if (!strcmp(v, "C_ONLY")) c_only++;
    else if (!strcmp(v, "MIR_ONLY")) m_only++;
    else if (!strcmp(v, "FAULT")) faults++;
    else refused++;
    executed[i] = mm.built && mm.ran;
    values[i] = mm.value;
    printf("CASE %-28s verdict=%-12s c=%s value=%llu | mir=%s value=%llu stage=%llu code=%llu runtime=%llu\n",
           CORPUS[i].name, v, c.built ? (c.ran ? "ran" : "built") : "REFUSE",
           (unsigned long long)c.value, mm.built ? (mm.ran ? "ran" : "built") : "REFUSE",
           (unsigned long long)mm.value, (unsigned long long)mm.stage,
           (unsigned long long)mm.code, (unsigned long long)mm.runtime);
    const Known *k = known(KNOWN, sizeof KNOWN / sizeof KNOWN[0], CORPUS[i].name);
    if (k) {
      printf("KNOWN %-28s owner=%s pinned=[stage %llu code %llu] measured=[stage %llu code %llu]\n",
             CORPUS[i].name, k->owner, (unsigned long long)k->stage, (unsigned long long)k->code,
             (unsigned long long)mm.stage, (unsigned long long)mm.code);
      CHECK(!strcmp(v, "C_ONLY") && mm.stage == k->stage && mm.code == k->code,
            "%s: the known divergence still has its pinned signature (verdict %s, stage %llu, code %llu); "
            "re-measure it rather than delete it", CORPUS[i].name, v, (unsigned long long)mm.stage,
            (unsigned long long)mm.code);
    } else {
      CHECK(!strcmp(v, "AGREE") || !strcmp(v, "REFUSED_BOTH"),
            "%s: the two producers reach the same verdict (%s)", CORPUS[i].name, v);
    }
    free(keep[0]);
    free(keep[1]);
  }
  /* One object comparison per distinct module file. */
  unsigned objects = 0, objects_matched = 0;
  for (size_t i = 0; i < CORPUS_N; i++) {
    const char *paths[2] = {CORPUS[i].a, CORPUS[i].b};
    for (int k = 0; k < 2 && paths[k]; k++) {
      int seen = 0;
      for (size_t j = 0; j < i && !seen; j++)
        seen = !strcmp(CORPUS[j].a, paths[k]) || (CORPUS[j].b && !strcmp(CORPUS[j].b, paths[k]));
      for (int kk = 0; kk < k && !seen; kk++) seen = !strcmp(paths[kk], paths[k]);
      if (seen) continue;
      size_t len = 0;
      uint8_t *text = readall(paths[k], &len);
      if (!text) continue;
      NtFInput in = {paths[k], (const char *)text, len};
      objects++;
      objects_matched += compare_objects(m, paths[k], &in);
      free(text);
    }
  }
  for (size_t i = 0; i < REFUSALS_N; i++) {
    NtFInput in = {REFUSALS[i].name, REFUSALS[i].text, strlen(REFUSALS[i].text)};
    Side c, mm;
    reference(&in, 1, &c);
    chain(m, &in, 1, &mm, NULL);
    const char *v = verdict(&c, &mm);
    cases++;
    if (!strcmp(v, "REFUSED_BOTH")) refused++;
    printf("REFUSAL %-24s verdict=%-12s c=E%llu mir=E%llu stage=%llu runtime=%llu\n", REFUSALS[i].name, v,
           (unsigned long long)c.code, (unsigned long long)mm.code, (unsigned long long)mm.stage,
           (unsigned long long)mm.runtime);
    CHECK(!strcmp(v, "REFUSED_BOTH") && mm.code != 0 && mm.stage != 0,
          "%s: both producers refuse, and the chain names a stage and a code", REFUSALS[i].name);
    CHECK(c.code == REFUSALS[i].c_code && mm.code == REFUSALS[i].mir_code,
          "%s: each producer refuses with its own measured code (C %llu, chain %llu; pinned %llu, %llu)",
          REFUSALS[i].name, (unsigned long long)c.code, (unsigned long long)mm.code,
          (unsigned long long)REFUSALS[i].c_code, (unsigned long long)REFUSALS[i].mir_code);
  }
  unsigned join_refused = 0, join_agree = 0, join_wrong = 0;
  for (size_t i = 0; i < JOINS_N; i++) {
    NtFInput in = {JOINS[i].name, JOINS[i].text, strlen(JOINS[i].text)};
    Side c, mm;
    reference(&in, 1, &c);
    chain(m, &in, 1, &mm, NULL);
    if (!strcmp(JOINS[i].name,"out-byte-preserves-family") || !strcmp(JOINS[i].name,"in-byte-snapshot") || !strcmp(JOINS[i].name,"out-high-byte")) {
      CHECK(compare_objects(m,JOINS[i].name,&in),"narrow param contracts match reference: %s",JOINS[i].name);
    }
    cases++;
    int refused = !mm.built && mm.runtime == 0;
    int agrees = mm.built && mm.ran && c.built && c.ran && mm.value == c.value;
    join_refused += refused;
    join_agree += agrees;
    join_wrong += !refused && !agrees;
    printf("JOIN %-20s c=%s value=%llu | mir=%s value=%llu stage=%llu code=%llu outcome=%s\n", JOINS[i].name,
           c.built ? (c.ran ? "ran" : "built") : "REFUSE", (unsigned long long)c.value,
           mm.built ? (mm.ran ? "ran" : "built") : "REFUSE", (unsigned long long)mm.value,
           (unsigned long long)mm.stage, (unsigned long long)mm.code, refused ? "refused" : agrees ? "agrees" : "WRONG");
    CHECK(agrees,
          "%s: the chain executes and returns the reference's value; it built and returned %llu "
          "where the reference %s %llu",
          JOINS[i].name, (unsigned long long)mm.value, c.built ? "returned" : "refused, code",
          (unsigned long long)(c.built ? c.value : c.code));
    if (JOINS[i].code)
      CHECK(refused && mm.stage == JOINS[i].stage && mm.code == JOINS[i].code,
            "%s: the chain refuses at stage %llu with code %llu, pinned stage %llu code %llu",
            JOINS[i].name, (unsigned long long)mm.stage, (unsigned long long)mm.code,
            (unsigned long long)JOINS[i].stage, (unsigned long long)JOINS[i].code);
    CHECK(c.built && c.ran, "%s: the reference runs the program, so a refusal here is a refusal of a program "
                            "the language admits", JOINS[i].name);
  }
  printf("JOIN_TALLY rows=%zu refused=%u agree=%u wrong=%u\n", JOINS_N, join_refused, join_agree, join_wrong);
  for (size_t i = 0; i < CHAIN_REFUSALS_N; i++) {
    NtFInput one = {CHAIN_REFUSALS[i].name, CHAIN_REFUSALS[i].text, strlen(CHAIN_REFUSALS[i].text)};
    Side c, mm;
    reference(&one, 1, &c);
    chain(m, &one, 1, &mm, NULL);
    cases++;
    printf("CHAIN_REFUSAL %-22s c=%s value=%llu | mir stage=%llu code=%llu\n", CHAIN_REFUSALS[i].name,
           c.built ? (c.ran ? "ran" : "built") : "REFUSE", (unsigned long long)c.value,
           (unsigned long long)mm.stage, (unsigned long long)mm.code);
    CHECK(!mm.built && mm.runtime == 0 && mm.stage == CHAIN_REFUSALS[i].stage && mm.code == CHAIN_REFUSALS[i].code,
          "%s: the chain refuses by name at stage %llu code %llu (got stage %llu code %llu)",
          CHAIN_REFUSALS[i].name, (unsigned long long)CHAIN_REFUSALS[i].stage,
          (unsigned long long)CHAIN_REFUSALS[i].code, (unsigned long long)mm.stage,
          (unsigned long long)mm.code);
  }
  for (size_t i = 0; i < STUB_PAIRS_N; i++) {
    NtFInput two[2] = {{"a6lib.ntasm", STUB_PAIRS[i].lib, strlen(STUB_PAIRS[i].lib)},
                       {"a6app.ntasm", STUB_PAIRS[i].app, strlen(STUB_PAIRS[i].app)}};
    Side c, mm;
    reference(two, 2, &c);
    chain(m, two, 2, &mm, NULL);
    cases++;
    const char *v = verdict(&c, &mm);
    printf("STUB_PAIR %-18s verdict=%-12s c=%llu/E%llu mir=%llu/E%llu stage=%llu\n", STUB_PAIRS[i].name, v,
           (unsigned long long)c.value, (unsigned long long)c.code, (unsigned long long)mm.value,
           (unsigned long long)mm.code, (unsigned long long)mm.stage);
    if (STUB_PAIRS[i].linked) {
      CHECK(!strcmp(v, "AGREE"), "%s: both producers link the imported stub and return the same value",
            STUB_PAIRS[i].name);
      CHECK(compare_objects(m, STUB_PAIRS[i].name, two),
            "%s: the library object publishes the stub symbol as the reference does", STUB_PAIRS[i].name);
    } else {
      CHECK(!strcmp(v, "REFUSED_BOTH"), "%s: a local stub is not importable, both producers refuse",
            STUB_PAIRS[i].name);
    }
  }
  machine_instruction_parity_checks(m);
  nt_machine_close(m);
  printf("TALLY corpus=%zu c_executables=%u mir_executables=%u agree=%u diverge=%u c_only=%u "
         "mir_only=%u refused_both=%u faults=%u objects=%u objects_matched=%u\n",
         CORPUS_N, c_accept, m_accept, agree, diverge, c_only, m_only, refused, faults, objects,
         objects_matched);

  /* THE CANARY. */
  int hits = build_canary();
  printf("CANARY tree=%s needle_hits=%d\n", canary_root[0] ? canary_root : "-", hits);
  CHECK(hits == 1, "the canary needle occurs exactly once in machine_emit.nova (hits=%d)", hits);
  if (hits == 1) {
    NtDiagnostic cerr = {0};
    NtMachineImage *mut = nt_machine_open(canary_root, &cerr);
    CHECK(mut != NULL, "the mutated chain compiles and maps: E%u %s", cerr.code, cerr.message);
    if (mut) {
      unsigned moved = 0, still = 0, compared = 0;
      for (size_t i = 0; i < CORPUS_N; i++) {
        if (!executed[i]) continue;
        NtFInput in[2];
        uint8_t *keep[2] = {NULL, NULL};
        size_t n = 0;
        if (!load_case(CORPUS + i, in, &n, keep)) { free(keep[0]); free(keep[1]); continue; }
        Side mm;
        chain(mut, in, n, &mm, NULL);
        compared++;
        int changed = !(mm.built && mm.ran && mm.value == values[i]);
        moved += changed;
        still += !changed;
        printf("CANARY %-28s original=%llu mutated=%s%llu %s\n", CORPUS[i].name,
               (unsigned long long)values[i], mm.built ? "" : "REFUSE:",
               (unsigned long long)(mm.built ? mm.value : mm.code), changed ? "MOVED" : "same");
        free(keep[0]);
        free(keep[1]);
      }
      printf("CANARY_TALLY compared=%u moved=%u unchanged=%u\n", compared, moved, still);
      CHECK(moved > 0, "PROOF_INVALID: replacing machine_emit's add by sub moved no executable result, so the "
                       "executables were not emitted by machine_emit");
      CHECK(still > 0, "a mutation that moves EVERY result is not aimed at the addition; at least one program "
                       "without an addition must keep its value");
      nt_machine_close(mut);
    }
  }
  remove_canary();
  printf("NTASM_NOVA_MACHINE_CORPUS checks=%u failures=%u cases=%u\n", checks, failures, cases);
  return failures ? 1 : 0;
}
