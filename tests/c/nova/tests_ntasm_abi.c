/* THE FEATURE-TEST MACRO, REQUESTED RATHER THAN INHERITED.
 *
 * This file is built with -std=c11, which sets __STRICT_ANSI__ and therefore
 * asks the C library for the ISO C surface and nothing more. Its ONLY POSIX
 * dependency is <dirent.h> -- opendir/readdir/closedir in the two direction
 * scans, which walk compiler/nova and are the whole structural half of
 * the drift detector.
 * Without a level named here, that surface arrives because the C library
 * DEFAULTS to _DEFAULT_SOURCE when no feature-test macro is given, and a
 * default is an implementation choice rather than a contract.
 *
 * WHAT WAS MEASURED, because the obvious story about this is WRONG on the
 * libc this suite runs on. The expected failure -- "-std=c11 hides opendir
 * and the build breaks with an implicit declaration" -- DOES NOT REPRODUCE
 * here: no feature-test setting withdraws it. Withholding _DEFAULT_SOURCE,
 * _BSD_SOURCE and _SVID_SOURCE and pinning _POSIX_C_SOURCE to 199309L still
 * compiles clean, because glibc declares opendir, readdir and closedir with
 * NO feature-test guard around them at all (/usr/include/dirent.h: the
 * opendir declaration is unguarded; only fdopendir and the reentrant forms
 * sit behind __USE_XOPEN2K8 / __USE_POSIX). So a proof written against that
 * story measures NOTHING here and would report success without having
 * exercised the defect. It is stated here instead of being assumed.
 *
 * So the portability criterion this change is measured against is the one
 * that DOES discriminate, and it is about composing with a build rather than
 * about surviving a libc: a harness that REQUESTS its POSIX surface must
 * still build when something else in the tree has already chosen that level,
 * which is ordinary for a harness compiled inside a larger build that sets
 * _POSIX_C_SOURCE once globally. The #ifndef below is what buys that; a bare
 * #define collides and breaks the build. Measured, with the perturbation
 * asserted to have applied, in MEM.md's entry for this change.
 *
 * So the dependency is declared, which is what makes it portable instead of
 * accidental. The two harnesses that already call mkdir state the same rule
 * in their own words and are the precedent, not a new convention:
 *   tests_ntasm_registry.c:89    #define _POSIX_C_SOURCE 200809L
 *   tests_ntasm_macro_expand.c:31 "this file is built with -std=c11, which
 *                                otherwise hides dirent.h, getpid and mkdir
 *                                behind the feature-test macro"
 *
 * The 200809L level is the one both of them ask for. It is defined BEFORE any
 * header, because a feature-test macro that arrives after the first #include
 * is a macro that changed nothing, and that is the shape of an edit that
 * reports success while measuring nothing.
 *
 * AND THIS FILE CALLS NO mkdir, which is why the plan's "portabilite de
 * mkdir" is not a call site here and this lot did not invent one: the token
 * census over this source returns zero for mkdir, _mkdir, CreateDirectoryA,
 * CreateDirectoryW, system, popen, mkdtemp and sys/stat.h. What the file
 * does is READ a directory, and <dirent.h> is the same POSIX declaration
 * family mkdir is declared on, so the portability criterion that applies
 * here is the one applied to the declaration rather than to an absent call.
 *
 * The census is recorded here as prose because a comment is the right place
 * for a fact about ABSENCE; it is not asserted by any check, and a reader
 * who wants it re-derived should re-derive it rather than trust this line. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
static unsigned checks,failures,cases;static const uint64_t guard=UINT64_C(0xcccccccccccccccc);
#define CHECK(c,m) do{checks++;if(!(c)){failures++;fprintf(stderr,"FAIL %s\n",m);}}while(0)
static char*load(const char*p,size_t*n){FILE*f=fopen(p,"rb");if(!f)return NULL;fseek(f,0,SEEK_END);long z=ftell(f);fseek(f,0,SEEK_SET);char*b=z>=0?malloc((size_t)z+1):NULL;if(!b||fread(b,1,(size_t)z,f)!=(size_t)z){free(b);fclose(f);return NULL;}fclose(f);b[z]=0;*n=(size_t)z;return b;}
/* Twenty five words: the direction conformance probe also checks the three
 * scalar ABI queries in out[16..18], the refused short buffer query in out[22]
 * and c_conversion's reading of the rule in out[24], and selects the defect it
 * exercises through out[20] and out[21]. run_mode hands over only the words
 * asked for, so the legacy four word contract is untouched. */
typedef struct{uint64_t returned,runtime,out[25];}Run;
static Run run_mode(const NovaHostImage*i,const char*s,uint64_t words,uint64_t mode,uint64_t fifth,uint64_t sixth){Run r={.out={guard,guard,guard,guard,guard,guard,guard,guard,guard,guard,guard,guard,guard,guard,guard,guard,guard,guard,guard,guard,guard,guard,guard,guard}};NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"context init");r.out[4]=mode;r.out[5]=fifth;r.out[6]=sixth;uint64_t sh=nova_borrow_v2(&c,(void*)s,strlen(s),0),oh=nova_borrow_v2(&c,r.out,words*8,1);uint64_t a[]={sh,strlen(s),oh,words};r.returned=i->entry(&c,a,4);r.runtime=c.error;CHECK(nova_context_destroy_v2(&c),"context cleanup");return r;}
static Run run(const NovaHostImage*i,const char*s,uint64_t words){return run_mode(i,s,words,0,0,0);}
static void ok(const NovaHostImage*i,const char*n,const char*s,uint64_t f,uint64_t m,uint64_t p){Run r=run(i,s,4);cases++;checks++;if(r.returned||r.runtime||r.out[0]!=f||r.out[1]!=m||r.out[2]!=p||r.out[3]){failures++;fprintf(stderr,"FAIL ok %s ret=%llu out=%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
static void err(const NovaHostImage*i,const char*n,const char*s,uint64_t words,uint64_t code,uint64_t reason,uint64_t index,int untouched){Run r=run(i,s,words);cases++;checks++;int bad=r.returned!=code||r.runtime;if(untouched)bad|=r.out[0]!=guard||r.out[1]!=guard;else bad|=r.out[0]==guard||r.out[1]==guard||r.out[2]!=reason||r.out[3]!=index;if(bad){failures++;fprintf(stderr,"FAIL error %s ret=%llu out=%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
/* Query channel 1: abi.argument_register / abi.argument / abi.bound_family over
 * the parameter at (declaration ordinal, index). Writes out[4]=architectural
 * GPR number, out[5]=physical family, out[6]=bound family, out[7]=consumes. */
static void qarg(const NovaHostImage*i,const char*n,const char*s,uint64_t decl,uint64_t idx,uint64_t arch,uint64_t fam,uint64_t bound,uint64_t consumes){Run r=run_mode(i,s,8,1,decl,idx);cases++;checks++;int bad=r.returned||r.runtime||r.out[4]!=arch||r.out[5]!=fam||r.out[6]!=bound||r.out[7]!=consumes;if(bad){failures++;fprintf(stderr,"FAIL argument %s decl=%llu idx=%llu ret=%llu out=%llu,%llu,%llu,%llu\n",n,(unsigned long long)decl,(unsigned long long)idx,(unsigned long long)r.returned,(unsigned long long)r.out[4],(unsigned long long)r.out[5],(unsigned long long)r.out[6],(unsigned long long)r.out[7]);}}
/* Query channel 1 must stay sealed on a refusing source: out[4..7] untouched. */
static void qarg_sealed(const NovaHostImage*i,const char*n,const char*s,uint64_t code,uint64_t reason,uint64_t index){Run r=run_mode(i,s,8,0,0,0);cases++;checks++;int bad=r.returned!=code||r.runtime||r.out[2]!=reason||r.out[3]!=index||r.out[4]||r.out[5]||r.out[6]||r.out[7]!=guard;if(bad){failures++;fprintf(stderr,"FAIL sealed %s ret=%llu out=%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[2],(unsigned long long)r.out[3],(unsigned long long)r.out[4],(unsigned long long)r.out[7]);}}
/* The same seal on the 800 paths: the legacy verdict stands and no partial
 * answer reaches the caller, the seeded selector words are left as written. */
static void qarg_800(const NovaHostImage*i,const char*n,const char*s,uint64_t decl,uint64_t idx){Run r=run_mode(i,s,8,1,decl,idx);cases++;checks++;int bad=r.returned!=800||r.runtime||r.out[0]!=1||r.out[1]||r.out[2]!=4||r.out[3]||r.out[4]!=1||r.out[5]!=decl||r.out[6]!=idx||r.out[7]!=guard;if(bad){failures++;fprintf(stderr,"FAIL absent %s ret=%llu out=%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[4],(unsigned long long)r.out[5],(unsigned long long)r.out[6],(unsigned long long)r.out[7]);}}
/* Query channel 2: abi.collisions over the whole module. A 328 answer is
 * checked against the exact line and column of the offending token. */
static void coll(const NovaHostImage*i,const char*n,const char*s,uint64_t code,uint64_t reason,uint64_t index,uint64_t line,uint64_t column,uint64_t decls,uint64_t params){Run r=run_mode(i,s,8,2,0,0);cases++;checks++;int bad=r.returned!=code||r.runtime;if(bad==0&&code==0)bad|=r.out[0]!=decls||r.out[1]!=params||r.out[2]||r.out[3];else if(bad==0&&code==800)bad|=r.out[0]!=guard||r.out[1]!=guard||r.out[2]!=guard||r.out[3]!=guard;else if(bad==0)bad|=r.out[0]!=line||r.out[1]!=column||r.out[2]!=reason||r.out[3]!=index;if(bad){failures++;fprintf(stderr,"FAIL collisions %s ret=%llu want=%llu,%llu,%llu,%llu out=%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)line,(unsigned long long)column,(unsigned long long)reason,(unsigned long long)index,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3]);}}
/* A caller that passes fewer than eight words never reaches the query
 * channel: the legacy four-word verdict is written and the seeded selector
 * words are left exactly as the caller wrote them. */
static void legacy_sealed(const NovaHostImage*i,const char*n,const char*s,uint64_t words,uint64_t f,uint64_t m,uint64_t p){Run r=run_mode(i,s,words,1,0,0);cases++;checks++;int bad=r.returned||r.runtime||r.out[0]!=f||r.out[1]!=m||r.out[2]!=p||r.out[3]||r.out[4]!=1||r.out[5]||r.out[6]||r.out[7]!=guard;if(bad){failures++;fprintf(stderr,"FAIL legacy %s ret=%llu out=%llu,%llu,%llu,%llu,%llu,%llu,%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3],(unsigned long long)r.out[4],(unsigned long long)r.out[5],(unsigned long long)r.out[6]);}}
/* ===================== W5-L4 direction reader conformance ===================
 *
 * There is one owner of the parameter direction rule, abi.nova:78 (fn
 * direction), and three copies that must agree with it: calls.nova:74,
 * call_types.nova:21 and x64_lower_nxo.nova:2056. The four cannot be made one
 * function, because no module can import another here: every harness lists its
 * compiler inputs by path and nova.c:627 refuses an import that is not among
 * them, so adding an import to abi.nova would break the four other harnesses
 * that compile it and adding one to x64_lower_nxo.nova would break thirteen.
 * They are made one RULE instead, and the table below is the proof.
 *
 * Each row parses one real module, rewrites the span of the first parameter
 * of the first declaration to a decoy, and asks all four readers the same
 * question about that same forged span. The decoy is the reachable form of the
 * C1 resynchronisation the W4-8 audit describes, a parameter node whose span
 * no longer opens on a direction keyword. A parsed tree cannot hold one,
 * because parser.nova:337 demands keyword 29, 30 or 31 there, which is why
 * the divergence between the two families was latent and why this table is
 * the only gate of the suite able to see it.
 *
 * The entry is generated here and compiled as a second artifact, because
 * abi-entry.nova already owns the only main export of the first one.
 */
static const char *probe_entry =
"module abi_direction_probe;\n"
"import ntasm_ast;\n"
"import ntasm_parser;\n"
"import ntasm_nxo;\n"
"import abi;\n"
"import calls;\n"
"import call_types;\n"
"import x64_lower_nxo;\nimport c_conversion;\n"
"// Parses a real module, then rewrites the span of the first parameter of the\n"
"// first declaration to the decoy out[1]..out[2], and asks the four direction\n"
"// readers the same question about that forged span. out[20] selects which\n"
"// part of the query domain is broken and out[21] is the parameter index, so\n"
"// the direction word of a defect row stays perfectly readable and the 800\n"
"// under test can only come from the selected defect.\n"
"// out[4] abi.argument code, out[5] its consumes flag, out[6] its\n"
"// architectural number, out[7] its bound family, out[8]\n"
"// abi.consumes_argument, out[9] calls.check code, out[10] its 311 reason,\n"
"// out[11] call_types.check code, out[12] its 354 reason, out[13]\n"
"// x64_lower_nxo.build_framed_functions code, out[14] the arity calls.check\n"
"// expected, out[15] the node id of the forged parameter, out[16]\n"
"// abi.argument_register, out[17] abi.argument_family, out[18]\n"
"// abi.bound_family, out[22] the same abi.argument query answered into a\n"
"// three word buffer, which is the len(out)<4 refusal of parameter_families\n"
"// seen from a caller that supplies its own answer buffer. 0 means every answer\n"
"// was produced; 800 means the tree, the declaration or the decoy could not be\n"
"// built, so a harness failure is never read as a verdict. Every answer slot\n"
"// starts at 14757395258967641292, the guard the harness seeded, so a slot the\n"
"// entry was not allowed to write is still recognisable on the C side; the two\n"
"// selector words are read before that fill and are re-asserted as guard.\n// out[24] is c_conversion.direction_in_span over the same forged span.\n"
"export fn main(source:buf<u8>,out:buf<u64>)->u64 {\n"
"    if len(out)<25 { return 800; }\n"
"    let start:u64=out[1];\n"
"    let stop:u64=out[2];\n"
"    let sel:u64=out[20];\n"
"    let index:u64=out[21];\n"
"    let mut i:u64=4;\n"
"    while i<20 { out[i]=14757395258967641292; i=i+1; }\n"
"    out[20]=14757395258967641292;\n"
"    out[21]=14757395258967641292;\n"
"    out[23]=14757395258967641292;\n"
"    if stop<start || stop>len(source) { return 800; }\n"
"    let mut tree:ntasm_ast.Tree=ntasm_parser.parse(source,1);\n"
"    if tree.ok==false { ntasm_ast.release(tree); return 800; }\n"
"    let mut decl:u64=0;\n"
"    let mut param:u64=0;\n"
"    let mut id:u64=1;\n"
"    while id<=tree.node_count && decl==0 {\n"
"        let n:ntasm_ast.Node=ntasm_ast.node_at(tree,id);\n"
"        if n.kind==18 {\n"
"            decl=id;\n"
"            let mut c:u64=n.first_child;\n"
"            while c!=0 && param==0 {\n"
"                if c>tree.node_count { break; }\n"
"                let cn:ntasm_ast.Node=ntasm_ast.node_at(tree,c);\n"
"                if cn.kind==19 { param=c; }\n"
"                c=cn.next_sibling;\n"
"            }\n"
"        }\n"
"        id=id+1;\n"
"    }\n"
"    if decl==0 || param==0 { ntasm_ast.release(tree); return 800; }\n"
"    let at:u64=(param-1)*12;\n"
"    tree.node_words[at+6]=start;\n"
"    tree.node_words[at+7]=stop;\n"
"    out[15]=param;\n    out[24]=c_conversion.direction_in_span(source,start,stop);\n"
"    // out[20] breaks one part of the query domain and nothing else, so a row\n"
"    // that expects 800 proves the reader refused instead of answering.\n"
"    let mut qid:u64=decl;\n"
"    if sel==1 { qid=0; }\n"
"    if sel==2 { qid=tree.node_count+1; }\n"
"    if sel==3 { qid=1; }\n"
"    if sel==4 { qid=param; }\n"
"    if sel==5 { tree.ok=false; }\n"
"    let query:buf<u64>=alloc(runtime(),4);\n"
"    let acode:u64=abi.argument(source,tree,qid,index,query);\n"
"    out[4]=acode;\n"
"    if acode==0 { out[5]=query[3]; out[6]=query[0]; out[7]=query[2]; }\n"
"    rt_free(runtime(),query);\n"
"    out[8]=abi.consumes_argument(source,tree,qid,index);\n"
"    out[16]=abi.argument_register(source,tree,qid,index);\n"
"    out[17]=abi.argument_family(source,tree,qid,index);\n"
"    out[18]=abi.bound_family(source,tree,qid,index);\n"
"    // The same query answered into a three word buffer. abi.argument refuses\n"
"    // it, so this is the len(out)<4 path seen from a caller that owns its\n"
"    // answer buffer rather than from the fixed four word scratch of the\n"
"    // three scalar exports, which cannot reach it at all.\n"
"    let short:buf<u64>=alloc(runtime(),3);\n"
"    let mut k4:u64=0;\n"
"    while k4<3 { short[k4]=0; k4=k4+1; }\n"
"    out[22]=abi.argument(source,tree,qid,index,short);\n"
"    rt_free(runtime(),short);\n"
"    let co:buf<u64>=alloc(runtime(),6);\n"
"    let mut k1:u64=0;\n"
"    while k1<6 { co[k1]=0; k1=k1+1; }\n"
"    let ccode:u64=calls.check(source,tree,co);\n"
"    out[9]=ccode;\n"
"    if ccode==311 { out[10]=co[4]; out[14]=co[2]; }\n"
"    rt_free(runtime(),co);\n"
"    let to:buf<u64>=alloc(runtime(),4);\n"
"    let mut k2:u64=0;\n"
"    while k2<4 { to[k2]=0; k2=k2+1; }\n"
"    let tcode:u64=call_types.check(source,tree,to);\n"
"    out[11]=tcode;\n"
"    out[12]=0;\n"
"    if tcode==354 { out[12]=to[2]; }\n"
"    rt_free(runtime(),to);\n"
"    let table:buf<u64>=alloc(runtime(),1920);\n"
"    let mut k3:u64=0;\n"
"    while k3<1920 { table[k3]=0; k3=k3+1; }\n"
"    let built:ntasm_nxo.WriteResult=x64_lower_nxo.build_framed_functions(source,tree,1,3,table);\n"
"    out[13]=built.code;\n"
"    let bytes:buf<u8>=built.bytes;\n"
"    rt_free(runtime(),bytes);\n"
"    rt_free(runtime(),table);\n"
"    ntasm_ast.release(tree);\n"
"    return 0;\n"
"}\n";

/* ===================== W10-L4 the profile the rules read ==================
 *
 * abi.nova's 328 reasons 1 and 2 are the two rules the oracle scopes to
 * nx64-abi-v0, and their efi behaviour is a LATENT change: check refuses
 * every profile name but the two with 327 before either rule runs, so the
 * efi arm cannot be reached through check until the name itself is
 * accepted. abi.parameter_rules is the same code with the 327 name gate
 * lifted, and this entry drives it, so the arm is measured rather than
 * asserted.
 *
 * The profile a declaration reads is a SPAN IN THE SOURCE, so the entry
 * takes that span as an input and writes it onto the node that carries the
 * name, exactly as the direction probe writes a decoy onto a parameter
 * node. out[8] selects which node: 0 the dashed child of the declaration's
 * own `abi` clause, 1 the dashed child of the module's `default_abi`
 * clause, 2 neither, which leaves the profile the source spells. Both
 * clauses are present in the fixture that has them, and a fixture has one
 * or the other so that each row reads the precedence the oracle states:
 * an explicit clause over the module default.
 *
 * BOTH PASSES ARE ASKED OF EVERY ROW, in one call, because the two must
 * differ in a predicted way and the difference is the whole point.
 * out[0..3] is abi.parameter_rules: on a refusal the line, column, reason
 * and zero-based parameter index check reports, and on acceptance the
 * parameter count, the output register mask, zero and THE PROFILE THE
 * RULES READ. out[4..7] is abi.check over the same tree. A row whose
 * profile is nx64 requires the two to agree word for word, which is what
 * proves the extraction changed no nx64 verdict; a row whose profile is
 * efi requires parameter_rules to answer and check to refuse with 327,
 * which is what proves the efi arm exists and is still unreachable.
 *
 * out[12] is the declaration node id, out[13] the node whose span was
 * written, out[14] the profile read back, out[15] is never written. Every
 * answer slot starts at the guard the harness seeded, so a word this entry
 * was not allowed to write is still recognisable on the C side. The
 * selectors are read before anything is written and are not re-asserted.
 */
static const char *profile_entry =
"module abi_profile_probe;\n"
"import ntasm_ast;\n"
"import ntasm_parser;\n"
"import abi;\n"
"// The first kind 92 child of a node, or 0. A dashed name is always that\n"
"// node's only child, so the loop stops on the first one it can read.\n"
"fn first_dashed(tree:ntasm_ast.Tree,first:u64)->u64 {\n"
"    let mut d:u64=first;\n"
"    while d!=0 {\n"
"        if d>tree.node_count { return 0; }\n"
"        let dn:ntasm_ast.Node=ntasm_ast.node_at(tree,d);\n"
"        if dn.kind==92 { return d; }\n"
"        d=dn.next_sibling;\n"
"    }\n"
"    return 0;\n"
"}\n"
"export fn main(source:buf<u8>,out:buf<u64>)->u64 {\n"
"    if len(out)<16 { return 800; }\n"
"    let target:u64=out[8];\n"
"    let start:u64=out[9];\n"
"    let stop:u64=out[10];\n"
"    let ordinal:u64=out[11];\n"
"    if stop<start || stop>len(source) { return 800; }\n"
"    let mut tree:ntasm_ast.Tree=ntasm_parser.parse(source,1);\n"
"    if tree.ok==false { ntasm_ast.release(tree); return 800; }\n"
"    let mut seen:u64=0;\n"
"    let mut decl:u64=0;\n"
"    let mut id:u64=1;\n"
"    while id<=tree.node_count && decl==0 {\n"
"        let n:ntasm_ast.Node=ntasm_ast.node_at(tree,id);\n"
"        if n.kind==18 || n.kind==9 {\n"
"            if seen==ordinal { decl=id; }\n"
"            seen=seen+1;\n"
"        }\n"
"        id=id+1;\n"
"    }\n"
"    if decl==0 { ntasm_ast.release(tree); return 800; }\n"
"    out[12]=decl;\n"
"    let mut node:u64=0;\n"
"    if target==0 {\n"
"        let mut c:u64=ntasm_ast.node_at(tree,decl).first_child;\n"
"        while c!=0 && node==0 {\n"
"            if c>tree.node_count { break; }\n"
"            let cn:ntasm_ast.Node=ntasm_ast.node_at(tree,c);\n"
"            if cn.kind==28 { node=first_dashed(tree,cn.first_child); }\n"
"            c=cn.next_sibling;\n"
"        }\n"
"    } else if target==1 {\n"
"        let mut m:u64=1;\n"
"        while m<=tree.node_count && node==0 {\n"
"            let mn:ntasm_ast.Node=ntasm_ast.node_at(tree,m);\n"
"            if mn.kind==6 { node=first_dashed(tree,mn.first_child); }\n"
"            m=m+1;\n"
"        }\n"
"    }\n"
"    out[13]=node;\n"
"    if target<2 {\n"
"        if node==0 { ntasm_ast.release(tree); return 800; }\n"
"        let at:u64=(node-1)*12;\n"
"        tree.node_words[at+6]=start;\n"
"        tree.node_words[at+7]=stop;\n"
"    }\n"
"    let ruled:buf<u64>=alloc(runtime(),4);\n"
"    let mut k:u64=0;\n"
"    while k<4 { ruled[k]=0; k=k+1; }\n"
"    let rcode:u64=abi.parameter_rules(source,tree,decl,ruled);\n"
"    out[0]=rcode;\n"
"    if rcode==0 { out[1]=ruled[0];out[2]=ruled[1];out[3]=ruled[3]; }\n"
"    else { out[1]=ruled[0];out[2]=ruled[2];out[3]=ruled[3]; }\n"
"    out[14]=0;\n"
"    if rcode==0 { out[14]=ruled[3]; }\n"
"    rt_free(runtime(),ruled);\n"
"    let gate:buf<u64>=alloc(runtime(),4);\n"
"    let mut j:u64=0;\n"
"    while j<4 { gate[j]=0; j=j+1; }\n"
"    let gcode:u64=abi.check(source,tree,gate);\n"
"    out[4]=gcode;\n"
"    if gcode==0 { out[5]=gate[0];out[6]=gate[1];out[7]=gate[2]; }\n"
"    else { out[5]=gate[0];out[6]=gate[2];out[7]=gate[3]; }\n"
"    rt_free(runtime(),gate);\n"
"    ntasm_ast.release(tree);\n"
"    return 0;\n"
"}\n";

/* One decoy per row. The head is a module that parses, carries exactly one
 * .text section, one exported function with one bound in parameter and one
 * caller that calls it with one argument, and carries the decoy in a comment,
 * so the decoy text costs the parser nothing and its offset is known by
 * construction. */
static const char *probe_head =
"module m\n"
"target x86_64-nexora-uefi\n"
"section .text {\n"
"export fn g(in a:u64 @rcx)->u64\n"
"effects {}\n"
"clobbers {} {\n"
"return 5\n"
"}\n"
"fn main(in b:u64 @rcx)->u64\n"
"effects {}\n"
"clobbers {} {\n"
"call g(1)\n"
"return 0\n"
"}\n"
"}// ";
static char probe_source[1024];

/* The expected answers of all four readers under the unified whole-word rule.
 * The last column is the framed producer, whose parameter collector accepts
 * only a direction of exactly 1 and then refuses a source whose abi table is
 * empty with 328; it is the one place where a prefix copy of the rule is
 * visible on its own. `relay` is c_conversion's direction_in_span: 1,2,3, or 0. */
struct dir_row {
  const char *decoy;
  uint64_t abi_code, abi_consumes, abi_arch, abi_bound, consumes_argument;
  uint64_t calls_code, calls_reason, calls_arity;
  uint64_t ct_code, ct_reason;
  uint64_t framed, relay;
};
static const struct dir_row dir_rows[] = {
  /* the three real directions, and the two words that carry them */
  {"in",       0, 1, 0, 2, 1,   0, 0, 0,   0, 0, 328, 1},
  {"in  ",     0, 1, 0, 2, 1,   0, 0, 0,   0, 0, 328, 1},
  {"  in",     0, 1, 0, 2, 1,   0, 0, 0,   0, 0, 328, 1},
  {"\tin",     0, 1, 0, 2, 1,   0, 0, 0,   0, 0, 328, 1},
  {"in\t",     0, 1, 0, 2, 1,   0, 0, 0,   0, 0, 328, 1},
  {"out",      0, 0, 0, 2, 0, 311, 4, 0, 354, 4, 800, 2},
  {"inout",    0, 1, 0, 2, 1,   0, 0, 0,   0, 0, 800, 3},
  /* a longer word that starts with a direction: the prefix rule called the
   * first two out, the last two in, the third one inout, and each of them
   * said so to a different module */
  {"outbound", 800, 0, 0, 0, 800,   0, 0, 0,   0, 0, 800, 0},
  {"outer",    800, 0, 0, 0, 800,   0, 0, 0,   0, 0, 800, 0},
  {"inx",      800, 0, 0, 0, 800,   0, 0, 0,   0, 0, 800, 0},
  {"input",    800, 0, 0, 0, 800,   0, 0, 0,   0, 0, 800, 0},
  {"inoutbox", 800, 0, 0, 0, 800,   0, 0, 0,   0, 0, 800, 0},
  /* a span with no word in it, and a span with no byte in it */
  {"  ",       800, 0, 0, 0, 800,   0, 0, 0,   0, 0, 800, 0},
  {"",         800, 0, 0, 0, 800,   0, 0, 0,   0, 0, 800, 0},
};
#define DIR_ROWS ((unsigned)(sizeof dir_rows / sizeof dir_rows[0]))

static Run run_probe(const NovaHostImage *i, const char *s, uint64_t start,
                     uint64_t stop, uint64_t sel, uint64_t index)
{
  Run r = {.out = {guard,guard,guard,guard,guard,guard,guard,guard,guard,guard,
                   guard,guard,guard,guard,guard,guard,guard,guard,guard,guard,
                   guard,guard,guard,guard,guard}};
  NovaContextV2 c = {0};
  CHECK(nova_context_init_v2(&c), "probe context init");
  r.out[1] = start;
  r.out[2] = stop;
  r.out[20] = sel;
  r.out[21] = index;
  uint64_t sh = nova_borrow_v2(&c, (void *)s, strlen(s), 0);
  uint64_t oh = nova_borrow_v2(&c, r.out, 25 * 8, 1);
  uint64_t a[] = {sh, strlen(s), oh, 25};
  r.returned = i->entry(&c, a, 4);
  r.runtime = c.error;
  CHECK(nova_context_destroy_v2(&c), "probe context cleanup");
  return r;
}

/* One comparison of the conformance table. Every field a reader answers is one
 * check, and the first reader that disagrees with the owner of the rule is
 * named, so a drifted copy is reported as calls.nova or call_types.nova and not
 * as a word index. */
#define WANT(cond, label) do { checks++; if (!(cond) && !why) why = label; } while (0)

/* One row of the conformance table. The four reader verdicts are compared
 * field by field, and every word the entry is not allowed to write is
 * required to still carry the guard. */
static void dir_case(const NovaHostImage *i, const struct dir_row *row)
{
  size_t head = strlen(probe_head), decoy = strlen(row->decoy);
  if (head + decoy + 2 > sizeof probe_source) {
    CHECK(0, "probe source fits");
    return;
  }
  memcpy(probe_source, probe_head, head);
  memcpy(probe_source + head, row->decoy, decoy);
  probe_source[head + decoy] = '\n';
  probe_source[head + decoy + 1] = 0;
  Run r = run_probe(i, probe_source, head, head + decoy, 0, 0);
  cases++;
  const char *why = NULL;
  uint64_t live = row->abi_code == 0;
  WANT(r.returned == 0, "abi_direction_probe entry returned");
  WANT(r.runtime == 0, "abi_direction_probe runtime fault");
  WANT(r.out[0] == guard && r.out[3] == guard && r.out[19] == guard &&
       r.out[20] == guard && r.out[21] == guard && r.out[23] == guard,
       "a word the entry may not write was written");
  WANT(r.out[15] != 0 && r.out[15] != guard, "forged parameter node not found");
  /* abi.nova, the owner of the rule. */
  WANT(r.out[4] == row->abi_code, "abi.nova:78 abi.argument code");
  WANT(live ? r.out[5] == row->abi_consumes : r.out[5] == guard,
       "abi.nova:78 abi.argument consumes");
  WANT(live ? r.out[7] == row->abi_bound : r.out[7] == guard,
       "abi.nova:78 abi.argument bound");
  WANT(r.out[8] == row->consumes_argument,
       "abi.nova:457 abi.consumes_argument");
  /* The fixture is explicitly bound to rcx: a readable direction has no
   * default register or family and keeps bound family 2, an unreadable one is
   * refused by every one of the four exports and never answered 0. */
  WANT(r.out[16] == (live ? 0 : 800), "abi.nova:395 abi.argument_register");
  WANT(r.out[17] == (live ? 0 : 800), "abi.nova:409 abi.argument_family");
  WANT(r.out[18] == (live ? 2 : 800), "abi.nova:423 abi.bound_family");
  /* The same query into a three word buffer is refused whatever the four
   * word answer was, so the length check is a refusal and not a synonym. */
  WANT(r.out[22] == 800, "abi.nova:376 abi.argument short buffer");
  /* calls.nova:74 and call_types.nova:21 read the same span with no error
   * channel and keep the argument of a span they cannot read. */
  WANT(r.out[9] == row->calls_code, "calls.nova:74 calls.check code");
  WANT(r.out[11] == row->ct_code, "call_types.nova:21 call_types.check code");
  if (row->calls_code == 311) {
    WANT(r.out[10] == row->calls_reason, "calls.nova:74 calls.check reason");
    WANT(r.out[14] == row->calls_arity, "calls.nova:74 calls.check arity");
  } else {
    WANT(r.out[10] == guard, "calls.nova:74 sealed reason word");
    WANT(r.out[14] == guard, "calls.nova:74 sealed arity word");
  }
  WANT(row->ct_code == 354 ? r.out[12] == row->ct_reason : r.out[12] == 0,
       "call_types.nova:21 call_types.check reason");
  /* x64_lower_nxo.nova:2056, reached through the framed producer, whose
   * parameter collector admits a direction of exactly 1 only. */
  WANT(r.out[13] == row->framed,
       "x64_lower_nxo.nova:2056 build_framed_functions code"); WANT(r.out[24] == row->relay, "c_conversion.nova direction_in_span");
  if (why) {
    failures++;
    fprintf(stderr, "FAIL direction %s: %s", why,
            row->decoy[0] ? row->decoy : "(empty span)");
    for (unsigned k = 4; k < 19; k++)
      fprintf(stderr, " out[%u]=%llu", k, (unsigned long long)r.out[k]);
    fprintf(stderr, " out[22]=%llu out[24]=%llu ret=%llu rt=%llu\n",
            (unsigned long long)r.out[22], (unsigned long long)r.out[24], (unsigned long long)r.returned,
            (unsigned long long)r.runtime);
  }
}

/* ===================== W6-L1 error channel of the four exports ==============
 *
 * The table above already drives a readable tree, a real function node and a
 * direction word that is garbage into all four exports. This block walks the
 * other refusals parameter_families can answer, one at a time, with the
 * direction word left perfectly readable in every row, so a row that expects
 * 800 proves that the reader refused instead of answering 0. out[20] breaks one
 * part of the query domain and nothing else:
 *   0 the declaration node the probe found, the control row
 *   1 a declaration id of 0                       abi.nova:345
 *   2 a declaration id past the last node          abi.nova:345
 *   3 the root node, neither a function nor an import
 *                                                    abi.nova:347
 *   4 the parameter node, a kind 19 and not a declaration
 *                                                    abi.nova:347
 *   5 a tree whose ok flag has been cleared         abi.nova:344 and :397
 *   7 a parameter index past the end of the signature, which is not a
 *     refusal at all and must keep answering the four zeros
 * The len(out)<4 refusal is the out[22] word of every row, because the three
 * scalar exports allocate their own four word scratch and cannot reach it.
 */
struct sel_row {
  const char *name, *decoy;
  uint64_t sel, index;
  uint64_t code, arg_consumes, arg_arch, arg_bound, consumes_argument;
  uint64_t reg, fam, bfam, short_code;
};
static const struct sel_row sel_rows[] = {
  {"control readable",        "in", 0, 0,   0, 1, 0, 2, 1,   0, 0, 2, 800},
  {"id zero",                 "in", 1, 0, 800, 800, 0, 0, 800, 800, 800, 800, 800},
  {"id past the tree",        "in", 2, 0, 800, 800, 0, 0, 800, 800, 800, 800, 800},
  {"root is not a declaration","in", 3, 0, 800, 800, 0, 0, 800, 800, 800, 800, 800},
  {"parameter is not a declaration","in", 4, 0, 800, 800, 0, 0, 800, 800, 800, 800, 800},
  {"unreadable tree",         "in", 5, 0, 800, 800, 0, 0, 800, 800, 800, 800, 800},
  {"index past the signature","in", 7, 15,  0, 0, 0, 0, 0,   0, 0, 0, 800},
};
#define SEL_ROWS ((unsigned)(sizeof sel_rows / sizeof sel_rows[0]))

/* One row of the error channel table. The four exports are compared against
 * each other at run time: a row that expects 800 requires all four to answer
 * 800, and a row that expects an answer requires all four to answer 0, so a
 * sibling that swallowed the refusal turns this row red on its own. */
static void sel_case(const NovaHostImage *i, const struct sel_row *row)
{
  size_t head = strlen(probe_head), decoy = strlen(row->decoy);
  if (head + decoy + 2 > sizeof probe_source) {
    CHECK(0, "probe source fits");
    return;
  }
  memcpy(probe_source, probe_head, head);
  memcpy(probe_source + head, row->decoy, decoy);
  probe_source[head + decoy] = '\n';
  probe_source[head + decoy + 1] = 0;
  Run r = run_probe(i, probe_source, head, head + decoy, row->sel, row->index);
  cases++;
  const char *why = NULL;
  uint64_t live = row->code == 0;
  WANT(r.returned == 0, "abi_direction_probe entry returned");
  WANT(r.runtime == 0, "abi_direction_probe runtime fault");
  WANT(r.out[0] == guard && r.out[3] == guard && r.out[19] == guard &&
       r.out[20] == guard && r.out[21] == guard && r.out[23] == guard,
       "a word the entry may not write was written");
  WANT(r.out[15] != 0 && r.out[15] != guard, "forged parameter node not found");
  WANT(r.out[4] == row->code, "abi.nova:374 abi.argument");
  WANT(live ? r.out[5] == row->arg_consumes : r.out[5] == guard,
       "abi.nova:374 abi.argument consumes");
  WANT(live ? r.out[6] == row->arg_arch : r.out[6] == guard,
       "abi.nova:374 abi.argument arch");
  WANT(live ? r.out[7] == row->arg_bound : r.out[7] == guard,
       "abi.nova:374 abi.argument bound");
  WANT(r.out[8] == row->consumes_argument, "abi.nova:457 abi.consumes_argument");
  WANT(r.out[16] == row->reg, "abi.nova:395 abi.argument_register");
  WANT(r.out[17] == row->fam, "abi.nova:409 abi.argument_family");
  WANT(r.out[18] == row->bfam, "abi.nova:423 abi.bound_family");
  WANT(r.out[22] == row->short_code, "abi.nova:376 abi.argument short buffer"); WANT(r.out[24] == 1, "c_conversion.nova direction_in_span reads no tree");
  /* The runtime comparison, spelled out rather than assumed. The three scalar
   * exports answer different words of one verdict, so what they must agree on
   * is the error channel and not the value: a refusal row wants all four at
   * 800, an answer row wants none of them at 800, so a single sibling that
   * swallowed the refusal turns this row red on its own. */
  uint64_t four[4] = {r.out[8], r.out[16], r.out[17], r.out[18]};
  unsigned refusals = 0;
  for (unsigned k = 0; k < 4; k++) refusals += four[k] == 800;
  WANT(refusals == (live ? 0u : 4u),
       live ? "a live query was refused by a sibling export"
            : "a refused query was answered by a sibling export");
  if (why) {
    failures++;
    fprintf(stderr, "FAIL refusal %s (sel=%llu index=%llu): %s",
            row->name, (unsigned long long)row->sel,
            (unsigned long long)row->index, why);
    for (unsigned k = 4; k < 19; k++)
      fprintf(stderr, " out[%u]=%llu", k, (unsigned long long)r.out[k]);
    fprintf(stderr, " out[22]=%llu out[24]=%llu ret=%llu rt=%llu\n",
            (unsigned long long)r.out[22], (unsigned long long)r.out[24], (unsigned long long)r.returned,
            (unsigned long long)r.runtime);
  }
}

/* The fixture a profile row is asked about. A real module with a real `.text`
 * section and one exported function whose `n` parameters are all unbound `in`
 * u64, which is the shape the oracle was measured on for both profiles: it is
 * the only shape in which the count rule and the fifth-parameter rule are
 * both reachable, because a bound parameter would draw a rule of its own
 * first. A fixture carries the module default, the declaration clause, or
 * neither, never both clauses at once, so that a row reading the default is
 * not answered by the declaration instead.
 *
 * The two profile spellings ride at the end of the last line inside a
 * comment, after a marker no other byte of the source can produce, so their
 * offsets are known by construction and cost the parser nothing. */
#define PROF_MARK "//PROF"
#define PROF_NX "nx64-abi-v0"
#define PROF_EF "efi-x64-v0"
/* THE FIXTURE BUFFER, and the truncation rule it is written under.
 *
 * snprintf returns the number of bytes it WOULD have written, not the number
 * it did. Accumulating that return value without checking it is what made
 * this function write outside its own buffer, and it is measured rather than
 * argued: ASan reports
 *
 *   ERROR: AddressSanitizer: global-buffer-overflow ... WRITE of size 13
 *   #3 prof_source tests_ntasm_abi.c:581
 *   0x... is located 4 bytes after global variable 'prof_buf' ... of size 8192
 *
 * driven by a row asking for more parameters than the buffer holds. Two
 * things go wrong at once and both are silent: `at` passes the end of the
 * buffer, and then `sizeof prof_buf - at` UNDERFLOWS to a size_t near
 * SIZE_MAX, so the remaining writes are told they have almost the whole
 * address space. A single oversized row therefore corrupts memory rather than
 * refusing the fixture, and the fixture is refused LONG afterwards by the
 * `at + 1 >= sizeof prof_buf` test below -- which is why the old code looked
 * guarded and was not: the guard ran after the writes it was guarding.
 *
 * So every write is checked BEFORE the next offset is derived from it: a
 * short write is a refusal, not a fixture. `prof_source` answers 0 and the
 * caller reports the row by name, which is the same shape a parse refusal
 * takes. This narrows what the buffer accepts; it does not widen it. */
static char prof_buf[8192];
/* Appends to prof_buf and refuses the fixture rather than truncating it.
 * Returns 1 on a complete append, 0 if it did not fit. */
static int prof_append(size_t *at, const char *fmt, ...)
{
  va_list ap;
  size_t room = sizeof prof_buf - *at;
  int w;
  if (room == 0) return 0;
  va_start(ap, fmt);
  w = vsnprintf(prof_buf + *at, room, fmt, ap);
  va_end(ap);
  /* w < 0 is an encoding failure. w >= room is a SHORT write: snprintf
   * reports what it would have needed, so this is the truncation signal and
   * it is checked before *at moves. */
  if (w < 0 || (size_t)w >= room) return 0;
  *at += (size_t)w;
  return 1;
}
static int prof_source(unsigned n, int has_default, int has_clause,
                       uint64_t *nx_at, uint64_t *ef_at)
{
  size_t at = 0;
  if (!prof_append(&at, "module m\ntarget x86_64-nexora-none\n%s"
                       "section .text {\nexport fn f(",
                   has_default ? "default_abi " PROF_NX "\n" : ""))
    return 0;
  for (unsigned i = 0; i < n; i++)
    if (!prof_append(&at, "%sin p%u:u64", i ? "," : "", i))
      return 0;
  if (!prof_append(&at, ")->u64\n%s", has_clause ? "abi " PROF_NX "\n" : ""))
    return 0;
  if (!prof_append(&at, "effects {}\nclobbers {} {\nreturn 0\n}\n}" PROF_MARK
                       PROF_NX "|" PROF_EF "\n"))
    return 0;
  const char *mark = strstr(prof_buf, PROF_MARK);
  if (!mark) return 0;
  /* An OFFSET INTO THE BUFFER, not an address: the entry indexes the source
   * it is lent, and it is lent prof_buf with its length, so a span of the
   * wrong kind is a length the entry refuses before it reads a node. */
  *nx_at = (uint64_t)(mark - prof_buf) + (sizeof PROF_MARK - 1);
  *ef_at = *nx_at + (sizeof PROF_NX - 1) + 1;
  return 1;
}

/* One row of the profile table. `target` is the node whose span the probe
 * writes: 0 the declaration's own `abi` clause, 1 the module `default_abi`,
 * 2 neither, so the profile is the one the source spells. `profile` is the
 * spelling written there, 1 nx64 and 2 efi, and 0 for the two rows that read
 * the source as it stands.
 *
 * `code`, `reason` and `index` are what abi.parameter_rules must answer, and
 * `gate` is what abi.check must answer INSTEAD, which is the whole point of
 * asking both: the two agree on every nx64 row and must disagree on every
 * efi one, because the efi arm exists and the name that would reach it does
 * not parse. */
struct prof_row {
  const char *name;
  unsigned params;
  int has_default, has_clause, target, profile;
  uint64_t code, reason, index, gate;
};
static const struct prof_row prof_rows[] = {
  /* nx64: the two rules stand exactly as they always have, and check, which
   * runs the same code, must agree word for word. */
  {"nx64 fifth unbound", 5, 0, 1, 0, 1, 328, 2, 4, 328},
  {"nx64 fifteen unbound", 15, 0, 1, 0, 1, 328, 1, 14, 328},
  {"nx64 sixteen unbound", 16, 0, 1, 0, 1, 328, 1, 14, 328},
  {"nx64 through the module default", 5, 1, 0, 1, 1, 328, 2, 4, 328},
  {"nx64 with no clause at all", 5, 0, 0, 2, 0, 328, 2, 4, 328},
  {"nx64 default with no clause", 5, 1, 0, 2, 0, 328, 2, 4, 328},
  /* efi: the same signatures are legal, and the oracle accepts all of them.
   * check now admits EFI: runtime tests prove calls with 0/5/15/64 arguments. */
  {"efi fifth unbound", 5, 0, 1, 0, 2, 0, 0, 0, 0},
  {"efi eight unbound", 8, 0, 1, 0, 2, 0, 0, 0, 0},
  {"efi fifteen unbound", 15, 0, 1, 0, 2, 0, 0, 0, 0},
  {"efi sixteen unbound", 16, 0, 1, 0, 2, 0, 0, 0, 0},
  {"efi sixty-four unbound", 64, 0, 1, 0, 2, 0, 0, 0, 0},
  {"efi through the module default", 5, 1, 0, 1, 2, 0, 0, 0, 0},
};
#define PROF_ROWS ((unsigned)(sizeof prof_rows / sizeof prof_rows[0]))

static Run run_profile(const NovaHostImage *i, const char *s, uint64_t target,
                       uint64_t start, uint64_t stop, uint64_t ordinal)
{
  Run r = {.out = {guard,guard,guard,guard,guard,guard,guard,guard,guard,guard,
                   guard,guard,guard,guard,guard,guard}};
  NovaContextV2 c = {0};
  CHECK(nova_context_init_v2(&c), "profile context init");
  r.out[8] = target;
  r.out[9] = start;
  r.out[10] = stop;
  r.out[11] = ordinal;
  uint64_t sh = nova_borrow_v2(&c, (void *)s, strlen(s), 0);
  uint64_t oh = nova_borrow_v2(&c, r.out, 16 * 8, 1);
  uint64_t a[] = {sh, strlen(s), oh, 16};
  r.returned = i->entry(&c, a, 4);
  r.runtime = c.error;
  CHECK(nova_context_destroy_v2(&c), "profile context cleanup");
  return r;
}

/* One row of the profile table. Every field either pass answers is compared,
 * and the first disagreement is named, so a red row says which layer moved
 * and not only that a number did. */
static void prof_case(const NovaHostImage *i, const struct prof_row *row)
{
  uint64_t nx_at = 0, ef_at = 0;
  cases++;
  if (!prof_source(row->params, row->has_default, row->has_clause, &nx_at,
                   &ef_at)) {
    checks++;
    failures++;
    fprintf(stderr, "FAIL profile %s: fixture did not fit\n", row->name);
    return;
  }
  uint64_t want_profile = row->profile ? (uint64_t)row->profile : 1u;
  uint64_t at = row->profile == 2 ? ef_at : nx_at;
  uint64_t span = row->profile == 2 ? (uint64_t)sizeof PROF_EF - 1
                                    : (uint64_t)sizeof PROF_NX - 1;
  Run r = run_profile(i, prof_buf, (uint64_t)row->target, at, at + span, 0);
  const char *why = NULL;
  /* The Nova probe substitutes a profile span from the trailing comment.
   * Give the C oracle the equivalent actual source, not the unchanged nx64
   * spelling that the probe overwrote in its tree. */
  char oracle_source[sizeof prof_buf];
  int written=snprintf(oracle_source,sizeof oracle_source,"%s",prof_buf);
  if(row->profile==2 && row->target<2){
    const char *name=strstr(prof_buf,PROF_NX),*mark=strstr(prof_buf,PROF_MARK);
    if(!name || !mark || name>=mark)written=-1;
    else written=snprintf(oracle_source,sizeof oracle_source,"%.*s%s%s",(int)(name-prof_buf),prof_buf,PROF_EF,name+sizeof(PROF_NX)-1);
  }
  WANT(written>=0 && (size_t)written<sizeof oracle_source,"oracle profile source fits");
  if(written>=0 && (size_t)written<sizeof oracle_source){
    NtFInput input={"profile-oracle",oracle_source,(size_t)written};NtFProgram reference={0};
    int accepted=nt_frontend_compile(&input,1,&reference);
    WANT(accepted==(row->gate==0),"C oracle and full Nova ABI check agree");
    if(!accepted)WANT(reference.diagnostic_count && reference.diagnostics[0].span.line && reference.diagnostics[0].span.column,"C ABI refusal has a source position");
    printf("ABI_PROFILE_ORACLE name=%s accepted=%d nova_code=%llu\n",row->name,accepted,(unsigned long long)r.out[4]);
    nt_frontend_free(&reference);
  }
  WANT(r.returned == 0, "abi_profile_probe entry returned");
  WANT(r.runtime == 0, "abi_profile_probe runtime fault");
  WANT(r.out[15] == guard, "a word the profile entry may not write was written");
  WANT(r.out[12] != 0 && r.out[12] != guard, "no declaration found");
  if (row->target < 2)
    WANT(r.out[13] != 0 && r.out[13] != guard, "no node to write the profile on");
  else
    WANT(r.out[13] == 0, "a node was written on a row that forges nothing");
  /* abi.parameter_rules, the half that carries both profile-scoped rules. */
  WANT(r.out[0] == row->code, "abi.parameter_rules code");
  if (row->code == 0) {
    /* Acceptance is only meaningful with the profile it accepted under, so
     * the resolver is read back rather than assumed. */
    WANT(r.out[1] == row->params, "abi.parameter_rules parameter count");
    WANT(r.out[2] == 0, "abi.parameter_rules output mask");
    WANT(r.out[3] == want_profile, "abi.parameter_rules profile");
    WANT(r.out[14] == want_profile, "profile read back");
  } else {
    WANT(r.out[2] == row->reason, "abi.parameter_rules reason");
    WANT(r.out[3] == row->index, "abi.parameter_rules index");
    WANT(r.out[1] != guard && r.out[1] != 0, "abi.parameter_rules line");
    WANT(r.out[14] == 0, "a profile was read back from a refusal");
  }
  /* abi.check over the same tree. On nx64 the two layers must agree word for
   * word; on efi the rules must answer and the name gate must still refuse,
   * which is the fact that makes this change latent rather than live. */
  WANT(r.out[4] == row->gate, "abi.check code");
  if (want_profile == 1) {
    /* nx64: the extracted half and the pass that runs it must answer the
     * same four words, or the extraction moved a verdict. */
    for (unsigned k = 0; k < 4; k++)
      WANT(r.out[k] == r.out[4 + k], "the two layers disagree on an nx64 row");
  } else {
    /* EFI is now live: the full check publishes the validated declaration
     * and parameter counts instead of an early unsupported-name diagnostic. */
    WANT(row->gate == 0 && r.out[4] == 0, "EFI profile accepted by full ABI check");
    WANT(r.out[5] == 1 && r.out[7] == row->params, "EFI declaration and parameter census preserved");
  }
  if (why) {
    failures++;
    fprintf(stderr, "FAIL profile %s: %s", row->name, why);
    for (unsigned k = 0; k < 16; k++)
      fprintf(stderr, " out[%u]=%llu", k, (unsigned long long)r.out[k]);
    fprintf(stderr, " ret=%llu rt=%llu\n", (unsigned long long)r.returned,
            (unsigned long long)r.runtime);
  }
}

/* ===================== W6-L1 direction copy inventory ======================
 *
 * The table above is behavioural, so it can only ever see the four copies it
 * names: a fifth implementation of the rule added anywhere else would be
 * invisible to it and to every other gate of the suite, which is the residue
 * D5 of the W5 audit describes. This scan is the structural half. It walks
 * the modules of compiler/nova and records every top level function
 * whose name carries the word direction, so an extra copy is reported with
 * its module and its line, and a deleted copy is reported by name.
 *
 * A definition is the literal "fn <name>(" opening a line, indentation
 * ignored. A comment can never be read as one: abi.nova names the other three
 * copies in prose but never at the start of a line, and the compressed
 * call_types.nova:21 that closes with its own prose is still one definition.
 * No body text is compared here, because the bodies differ by helper name and
 * by line width and the semantics are the table's job, not a text diff's.
 */
#define NOVA_MODULE_DIR "compiler/nova"
/* THE HISTORY OF THE CONSTANT THAT WAS HERE, read because it is the shape
 * being removed and it is right about itself.
 *
 * 61 as of 2026-10-02: 59 before, plus c_conversion.nova, the C -> Nova
 * conversion (lot 62, "THE C -> NOVA CONVERSION, made executable", c_conversion.nova:6)
 * and machine_x64.nova, the READER for the Machine IR (machine_x64.nova:8,
 * "machine_ir.nova builds and verifies a Machine IR and nothing reads one to
 * produce a byte; this module is the reader"). Both are deliberate, both
 * declare themselves at their first line, and both carry a tests/ entry. The
 * constant was not raised with them: the failure the paragraph below was
 * written for, happening for the THIRD time.
 * 59 as of 2026-09-30: 58 before, plus ntir_inspect.nova, the READER for the
 * NTIR image. nxo_inspect.nova and pe_inspect.nova each had a counterpart for
 * their format and NTIR had none, so an NTIR could be built, verified and
 * serialised and nothing in the tree could read one back. That is a deliberate
 * addition to the directory this constant counts, which is the case the
 * comment below was written for.
 * 58 as of 2026-09-29: 57 before, plus ir_image.nova, the byte container that
 * gives NTIR and Machine IR something a reader can be handed. It was added at
 * 21:06 and this constant was not raised with it -- which is the failure the
 * comment below is about, happening once, in the tree, to the constant itself.
 * Earlier: 57 as of 2026-09-29, 56 as of 2026-09-27, 54 before that, plus
 * ntir.nova, the first intermediate representation in the tree, added by
 * wave 7, and machine_ir.nova, the Machine IR above it, added by wave 8. And
 * 57 as of 2026-09-29: 56 before that, plus macro_splice.nova, the module the
 * expansion stage and the seven splice passes moved out of validate.nova into,
 * because a producer that compiles objects cannot carry a forty one module
 * pipeline and the splice is the part of it that can be reached.
 *
 * And the shape of it, now that it has happened three times: this was a count
 * about a DIRECTORY, not about a list anybody maintains, so it moved on its
 * own whenever a module landed, and the only thing that turned it red was
 * somebody reading the red and naming the module. That is a weaker guarantee
 * than it looks, and it is the same shape as a hand-maintained list -- the
 * number is right about the directory and nothing enforces that it was raised
 * on purpose.
 *
 * WHY A COUNT AND A LIST BOTH FAIL, so neither is what replaced it. A count
 * cannot name a thing: the red said "61, expected 59" and the reader had to go
 * and diff a directory to learn which two files had moved. A list of sixty-one
 * names would name the offender, and it is the same weakness in a longer
 * dress -- a second copy of a directory, whose edit says nothing about whether
 * the addition was intended, and whose next omission is as invisible as the
 * last one was. Naming the unexpected module requires knowing the expected
 * set, so the only way out is to stop holding the set here at all.
 *
 * THE EXPECTED SET IS THE ONE THE TREE ALREADY KEEPS, and it was measured
 * before it was adopted rather than assumed. Every module of
 * compiler/nova is the subject of an entry under
 * tests/nova/tests that imports it: 61 module files, 106 entries,
 * 61 distinct `import <name>;` tokens, and the mapping is a BIJECTION onto
 * the 61 declared `module <name>;` names -- no entry token names a module that
 * is not in the directory, and no module in the directory is left unimported.
 * The five prose uses of the English word "import" in those entries are not
 * `import <name>;` and are not counted.
 *
 * So the tree already holds this set, in the project's own convention, and a
 * module cannot join it by appearing: it has to be given its entry, which is a
 * visible act in a reviewed file and the same act any other module in the tree
 * had to perform. That is the property the count never had.
 *
 * SO THIS SCAN NO LONGER COUNTS. It walks both directories, matches each
 * module's declared `module <name>;` against the names the entries import, and
 * reports BY NAME every module nothing imports (an addition nobody wired) and
 * every import nothing provides (a deletion, which the count could only have
 * caught as a smaller number). Neither check has a constant to be right, so
 * neither can be made green by raising one, and the failure no longer waits on
 * a reader to name the file for it. */
#define NOVA_MODULE_DIR "compiler/nova"
#define NOVA_ENTRY_DIR "tests/nova/tests"
#define MODULE_CAP 256
#define FOUND_CAP 64
#define NAME_CAP 64
#define FILE_CAP 256
struct known_copy { const char *file, *name; };
static const struct known_copy known_copies[] = {
  {"abi.nova", "direction"},
  {"calls.nova", "direction"},
  {"call_types.nova", "direction"},
  {"x64_lower_nxo.nova", "param_direction"},
};
#define KNOWN_COPIES ((unsigned)(sizeof known_copies / sizeof known_copies[0]))
/* NAMES THAT CARRY THE WORD AND NOT THE RULE. Added 7 October 2026, the day
 * the two scans below learned to read `export fn`: before that, every exported
 * definition of the tree was invisible to both of them, and three of the
 * invisible ones were named for direction. A name is not a rule, so each such
 * function is declared here with what it does instead, and the declaration is
 * checked rather than trusted: it must name exactly one definition (the name
 * scan), it must NOT carry the rule's shape (the shape scan), and when it
 * names an owner it relays to, its body must call that owner (the shape scan,
 * on the same whitespace-free body it confronts against the rule). A declared
 * relay that grew its own copy of the rule is red as a fifth implementation;
 * a relay that stopped asking the owner is red as a broken relay.
 *
 * c_conversion.nova held a fifth copy of the rule, `export fn direction`,
 * until this date. It was measured equal to the owner on the whole
 * conformance table above (twenty one checks of the out[24] column, all
 * green) and then replaced by a relay to abi.parameter_mode, the export A7
 * gave the owner; the measurement and the decision are in MEM.md under
 * « export fn ». */
struct named_not_copy { const char *file, *name, *relays_to; };
static const struct named_not_copy known_not_copies[] = {
  /* the span reader of the C conversion: it builds the parameter node from
   * the span and asks the owner */
  {"c_conversion.nova", "direction_in_span", "abi.parameter_mode("},
  /* maps the C NtFDirection values 3..6 (local, const, data, past the
   * catalogue) to "no Nova home"; it reads no source span */
  {"c_conversion.nova", "direction_has_no_nova_home", NULL},
};
#define NOT_COPIES ((unsigned)(sizeof known_not_copies / sizeof known_not_copies[0]))
struct found_copy { char file[FILE_CAP], name[NAME_CAP]; unsigned line; };
/* One row per module of NOVA_MODULE_DIR, kept so the entry walk can name the
 * one that is unimported. `named` is set when some tests/ entry imports the
 * module this file declares. */
struct mod_rec { char file[FILE_CAP], name[NAME_CAP]; int named; };
/* PRODUCTION ROOTS, declared, and the only modules of the directory that no
 * tests/ entry imports by construction. compiler/c/nova/
 * machine_driver.c compiles each one as the root of its own image (the
 * Machine IR producer and the Nova linker of `ntasm --backend mir`); an entry
 * is imported by nothing, and importing one from a tests/ entry would put two
 * `main` exports in one artifact. Added 7 October 2026 (A7). Both directions
 * are checked: a declared root that is absent from the directory is red, and
 * every other module still needs a tests/ entry that imports it. */
static const char *const production_roots[] = {
  "machine-driver-entry.nova",
  "machine-link-entry.nova",
};
#define PRODUCTION_ROOTS ((unsigned)(sizeof production_roots / sizeof production_roots[0]))
/* A word character, without pulling <ctype.h> in for six uses. */
static int word_char(int c)
{ return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
         (c >= '0' && c <= '9') || c == '_'; }

/* A check that reports a module and a line rather than a bare counter. */
#define WANT_AT(cond, ...) do { checks++; if (!(cond)) { failures++; \
    fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); } } while (0)

/* WHAT A DEFINITION IS, read off the reference compiler and not off the tree.
 * nova.c's `signatures` takes an optional `export` and then `fn` and the name,
 * and its lexer separates tokens by space, tab, CR or LF and drops `//` to
 * the end of the line. Both scans below used to accept only a line opening
 * with `fn `, so every `export fn` was invisible to them: measured on 7
 * October 2026, 2132 top level definitions in the 67 modules, 643 of them
 * exported, and the scans read exactly the 1489 private ones. Three of the
 * invisible ones were named for direction and one carried the rule.
 *
 * This reads the forms a line can open with: `fn NAME` and `export fn NAME`,
 * with any run of blanks between the words. It answers the width of NAME and
 * sets *from to its first byte, or answers 0 when the line opens no
 * definition. NAME is an identifier as the lexer reads one, so `(` ends it.
 *
 * WHAT IT CANNOT SEE, and what sees it instead. The grammar lets a definition
 * start mid line (`} fn f(`) or split its keywords over lines (`export` then
 * `fn` on the next one). None of the 2132 does, and a line reader cannot know
 * that, so token_definitions below reads the same modules a second way --
 * token by token, as the lexer does -- and the shape scan requires the two
 * counts to agree module by module. A definition this function misses is a
 * disagreement printed with its module, not a silence. */
static size_t def_name_at(const char *t, size_t p, size_t end, size_t *from)
{
  if (p + 7 <= end && memcmp(t + p, "export", 6) == 0 &&
      (t[p + 6] == ' ' || t[p + 6] == '\t')) {
    p += 6;
    while (p < end && (t[p] == ' ' || t[p] == '\t')) p++;
  }
  if (!(p + 3 <= end && memcmp(t + p, "fn", 2) == 0 &&
        (t[p + 2] == ' ' || t[p + 2] == '\t')))
    return 0;
  p += 2;
  while (p < end && (t[p] == ' ' || t[p] == '\t')) p++;
  size_t q = p;
  while (q < end && word_char((unsigned char)t[q])) q++;
  *from = p;
  return q - p;
}

/* The second reading. Every `fn` token at brace depth zero is a definition:
 * at depth zero the grammar holds only `module`, `import`, `struct` and
 * `export`/`fn` headers, and a record's fields are at depth one. Strings are
 * skipped with their escapes and `//` comments to the end of the line, the
 * two places where a brace or an `fn` is not code; Nova has no character
 * literal and no block comment, so there is no third. */
static unsigned token_definitions(const char *t, size_t n)
{
  unsigned defs = 0;
  long depth = 0;
  for (size_t i = 0; i < n;) {
    unsigned char c = (unsigned char)t[i];
    if (c == ' ' || c == '\t' || c == '\r' || c == '\n') { i++; continue; }
    if (c == '/' && i + 1 < n && t[i + 1] == '/') {
      while (i < n && t[i] != '\n') i++;
      continue;
    }
    if (c == '"') {
      size_t e = i + 1;
      while (e < n && t[e] != '"' && t[e] != '\n' && t[e] != '\r') {
        if (t[e] == '\\' && e + 1 < n) e++;
        e++;
      }
      i = e + 1;
      continue;
    }
    if (word_char(c)) {
      size_t e = i;
      while (e < n && word_char((unsigned char)t[e])) e++;
      if (depth == 0 && e - i == 2 && t[i] == 'f' && t[i + 1] == 'n') defs++;
      i = e;
      continue;
    }
    if (c == '{') depth++;
    else if (c == '}') depth--;
    i++;
  }
  return defs;
}

static void scan_direction_copies(void)
{
  struct found_copy found[FOUND_CAP];
  struct mod_rec mods[MODULE_CAP];
  unsigned nf = 0, nm = 0, modules = 0, overflow = 0, mod_overflow = 0;
  DIR *d = opendir(NOVA_MODULE_DIR);
  checks++;
  if (!d) {
    failures++;
    fprintf(stderr, "FAIL DIRECTION-SCAN cannot open %s\n", NOVA_MODULE_DIR);
    return;
  }
  struct dirent *e;
  while ((e = readdir(d)) != 0) {
    size_t len = strlen(e->d_name);
    if (len < 6 || strcmp(e->d_name + len - 5, ".nova") != 0) continue;
    if (e->d_name[0] == '.') continue;
    modules++;
    /* Recorded before the text is read, so a module that cannot be read is
     * still reported by its file name rather than vanishing from the census. */
    if (nm == MODULE_CAP) { mod_overflow++; }
    else { memset(&mods[nm], 0, sizeof mods[nm]);
           snprintf(mods[nm].file, FILE_CAP, "%s", e->d_name); nm++; }
    char path[512];
    snprintf(path, sizeof path, "%s/%s", NOVA_MODULE_DIR, e->d_name);
    size_t n = 0;
    char *text = load(path, &n);
    checks++;
    if (!text) {
      failures++;
      fprintf(stderr, "FAIL DIRECTION-SCAN cannot read %s\n", path);
      continue;
    }
    unsigned line = 1;
    for (size_t i = 0; i < n;) {
      size_t j = i;
      while (j < n && text[j] != '\n') j++;
      size_t p = i;
      while (p < j && (text[p] == ' ' || text[p] == '\t')) p++;
      /* `module <name>;`, the declaration the entry walk matches on. It is the
       * FIRST such line of the file; a later one is prose or a nested block,
       * and this scan reads the module, not the language. */
      if (p + 7 <= j && memcmp(text + p, "module ", 7) == 0 && nm &&
          mods[nm - 1].name[0] == 0) {
        size_t q = p + 7, from = q;
        while (q < j && text[q] != ';' && text[q] != ' ' && text[q] != '\t') q++;
        if (q > from && q - from < NAME_CAP) {
          memcpy(mods[nm - 1].name, text + from, q - from);
          mods[nm - 1].name[q - from] = 0;
        }
      }
      size_t from = 0, width = def_name_at(text, p, j, &from);
      if (width > 0) {
        char name[NAME_CAP];
        if (width > 0 && width < NAME_CAP) {
          memcpy(name, text + from, width);
          name[width] = 0;
          if (strstr(name, "direction")) {
            if (nf == FOUND_CAP) { overflow++; continue; }
            snprintf(found[nf].file, FILE_CAP, "%s", e->d_name);
            snprintf(found[nf].name, NAME_CAP, "%s", name);
            found[nf].line = line;
            nf++;
          }
        }
      }
      i = j + 1;
      line++;
    }
    free(text);
  }
  closedir(d);
  /* THE DERIVATION, and it replaces the count this file used to carry. The
   * expected module set is not written down here: it is the set of modules the
   * tree's own test entries import, read back from the tree on every run. A
   * module joins that set by being given an entry under NOVA_ENTRY_DIR, which
   * is a visible act in a reviewed file; it does not join by appearing in the
   * directory and moving a number, which is the failure this comment block
   * above records happening three times. Both directions are reported, by
   * name, because a count could only ever report the SIZE of a change. */
  {
    unsigned entries = 0, named = 0;
    checks++;
    DIR *t = opendir(NOVA_ENTRY_DIR);
    if (!t) {
      failures++;
      fprintf(stderr, "FAIL MODULE-SET cannot open %s, so no module can be "
                      "shown to be wired and every module would be reported\n",
              NOVA_ENTRY_DIR);
    } else {
      struct dirent *te;
      while ((te = readdir(t)) != 0) {
        size_t tl = strlen(te->d_name);
        if (tl < 6 || strcmp(te->d_name + tl - 5, ".nova") != 0) continue;
        if (te->d_name[0] == '.') continue;
        entries++;
        char epath[512];
        snprintf(epath, sizeof epath, "%s/%s", NOVA_ENTRY_DIR, te->d_name);
        size_t en = 0;
        char *etext = load(epath, &en);
        if (!etext) continue;   /* an unreadable entry is named by nothing */
        for (size_t i = 0; i + 6 <= en; i++) {
          if (etext[i] != 'i' || memcmp(etext + i, "import", 6) != 0) continue;
          if (i && word_char((unsigned char)etext[i - 1])) continue;
          size_t q = i + 6;
          while (q < en && (etext[q] == ' ' || etext[q] == '\t')) q++;
          size_t from = q;
          while (q < en && word_char((unsigned char)etext[q])) q++;
          size_t width = q - from;
          if (width == 0 || width >= NAME_CAP) continue;
          char iname[NAME_CAP];
          memcpy(iname, etext + from, width);
          iname[width] = 0;
          size_t z = q;
          while (z < en && (etext[z] == ' ' || etext[z] == '\t')) z++;
          if (z >= en || etext[z] != ';') continue;  /* prose, not an import */
          unsigned k = 0;
          for (; k < nm; k++)
            if (strcmp(mods[k].name, iname) == 0) break;
          checks++;
          if (k == nm) {
            failures++;
            fprintf(stderr, "FAIL MODULE-SET IMPORT-UNPROVIDED %s: entry "
                            "imports module %s and no module of %s declares it;"
                            " an entry outran the module directory\n",
                    te->d_name, iname, NOVA_MODULE_DIR);
          } else if (!mods[k].named) { mods[k].named = 1; named++; }
        }
        free(etext);
      }
      closedir(t);
      fprintf(stderr, "MODULE-SET modules=%u entries=%u imported=%u\n",
              modules, entries, named);
    }
    for (unsigned r = 0; r < PRODUCTION_ROOTS; r++) {
      unsigned present = 0;
      for (unsigned k = 0; k < nm; k++)
        present += strcmp(mods[k].file, production_roots[r]) == 0;
      WANT_AT(present == 1, "FAIL MODULE-SET ROOT-ABSENT %s is declared a production root "
              "and is not a module of %s", production_roots[r], NOVA_MODULE_DIR);
    }
    for (unsigned k = 0; k < nm; k++) {
      int root = 0;
      for (unsigned r = 0; r < PRODUCTION_ROOTS; r++)
        root |= strcmp(mods[k].file, production_roots[r]) == 0;
      if (root) continue;
      checks++;
      if (mods[k].name[0] == 0 || !mods[k].named) {
        failures++;
        fprintf(stderr, "FAIL MODULE-SET MODULE-UNNAMED %s: it declares module "
                        "%s and no entry under %s imports it. A module is "
                        "added to the tree by being given a tests/ entry that "
                        "imports it, not by appearing here.\n",
                mods[k].file, mods[k].name[0] ? mods[k].name : "<no module decl>",
                NOVA_ENTRY_DIR);
      }
    }
    WANT_AT(mod_overflow == 0,
            "FAIL MODULE-SET overflowed %u extra modules past MODULE_CAP %d",
            mod_overflow, MODULE_CAP);
  }
  WANT_AT(overflow == 0, "FAIL DIRECTION-SCAN overflowed %u extra copies",
          overflow);
  WANT_AT(nf == KNOWN_COPIES + NOT_COPIES,
          "FAIL DIRECTION-SCAN found %u functions named for direction, expected %u "
          "(%u declared copies and %u declared names that are not copies)",
          nf, KNOWN_COPIES + NOT_COPIES, KNOWN_COPIES, NOT_COPIES);
  for (unsigned k = 0; k < KNOWN_COPIES; k++) {
    unsigned hits = 0;
    for (unsigned f = 0; f < nf; f++)
      hits += strcmp(found[f].file, known_copies[k].file) == 0 &&
              strcmp(found[f].name, known_copies[k].name) == 0;
    WANT_AT(hits == 1,
            "FAIL DIRECTION-COPY-MISSING %s %s: %u definitions, expected 1",
            known_copies[k].file, known_copies[k].name, hits);
  }
  /* A declaration that names nothing is stale, and a stale exemption is the
   * one that would let the next function of that name through unseen. */
  for (unsigned k = 0; k < NOT_COPIES; k++) {
    unsigned hits = 0;
    for (unsigned f = 0; f < nf; f++)
      hits += strcmp(found[f].file, known_not_copies[k].file) == 0 &&
              strcmp(found[f].name, known_not_copies[k].name) == 0;
    WANT_AT(hits == 1,
            "FAIL DIRECTION-NOT-COPY-MISSING %s %s: %u definitions, expected 1; "
            "the declaration names nothing",
            known_not_copies[k].file, known_not_copies[k].name, hits);
  }
  for (unsigned f = 0; f < nf; f++) {
    int known = 0;
    for (unsigned k = 0; k < KNOWN_COPIES; k++)
      known |= strcmp(found[f].file, known_copies[k].file) == 0 &&
               strcmp(found[f].name, known_copies[k].name) == 0;
    for (unsigned k = 0; k < NOT_COPIES; k++)
      known |= strcmp(found[f].file, known_not_copies[k].file) == 0 &&
               strcmp(found[f].name, known_not_copies[k].name) == 0;
    if (!known) {
      failures++;
      checks++;
      fprintf(stderr,
              "FAIL DIRECTION-COPY-EXTRA %s:%u fn %s is a fifth implementation "
              "of the direction rule owned by abi.nova fn direction, or a name "
              "that must be declared as not one\n",
              found[f].file, found[f].line, found[f].name);
    }
  }
  checks++;
  if (nf == KNOWN_COPIES + NOT_COPIES) {
    for (unsigned f = 0; f < nf; f++) {
      int copy = 0;
      for (unsigned k = 0; k < KNOWN_COPIES; k++)
        copy |= strcmp(found[f].file, known_copies[k].file) == 0 &&
                strcmp(found[f].name, known_copies[k].name) == 0;
      fprintf(stderr, "%s %s:%u fn %s\n",
              copy ? "DIRECTION-COPY" : "DIRECTION-NAME-NOT-COPY",
              found[f].file, found[f].line, found[f].name);
    }
  }
}

/* ===================== D5: the direction rule by its SHAPE ================
 *
 * WHY THIS EXISTS, and it is the whole residual. scan_direction_copies above
 * anchors on the NAME: it records every top level function whose name carries
 * the word "direction" and reports any that is not one of the four declared.
 * That is a closed answer to "is there a fifth function CALLED direction", and
 * an open one to "is there a fifth IMPLEMENTATION of the rule". The
 * difference was not argued, it was watched: abi.nova's direction() copied
 * verbatim into clobbers.nova under the name read_span_word leaves the name
 * scan reporting its usual four copies and failing nothing. The residual of
 * rapport-vagues-1-5-20260927 section 8 item 5 is exactly that gap, and this
 * function is the closure of it.
 *
 * THE ANCHOR IS THE RULE, NOT THE NAME. A function carries the direction rule
 * when its body presents the ordered whole-word comparisons of the three
 * direction keywords against their answers:
 *
 *     inout -> 3     out -> 2     in -> 1
 *
 * in either of the two spellings this tree uses, because the copies were not
 * written by one hand:
 *
 *   literal    let inout_:buf<u8>="inout"; if same_bytes(...,inout_){return 3;}
 *              and calls.nova / call_types.nova, which route the same
 *              comparison through span_word instead.
 *   inlined    if n==5&&source[at]==105&&...{return 3;}
 *              which is x64_lower_nxo.nova's param_direction, spelling the
 *              keyword as its bytes because that module has no same_bytes.
 *
 * So there are TWO rule signatures among the four copies and both are
 * enumerated below. A detector that recognised only the literal spelling
 * would have measured zero false positives and still have missed one of the
 * four it exists to account for, which is the failure mode that produced the
 * original residual.
 *
 * MEASURED, not assumed: over the 1209 top level functions of the 58 modules
 * under compiler/nova, exactly FOUR carry the rule shape and they are
 * the four declared copies. Zero false positives. That number is what makes
 * this a check rather than a tautology, and it is re-asserted below on every
 * run: if a fifth function ever carries the shape, it is named with its
 * module and its line, whatever it is called.
 *
 * WHAT IT IS NOT. It does not read bodies semantically; it recognises two
 * surface spellings. A copy written through a lookup table, or through a
 * third spelling, would not carry either shape and would not be named. That
 * limit is the rule's own, stated here rather than left for a reader to
 * discover: this closes the residual against the spellings the tree uses, and
 * it says so in the log on every run. Closing it against an arbitrary
 * re-spelling needs equivalence over Nova bodies, which is a different
 * instrument and is not claimed here.
 */
#define RULE_NONE  0
#define RULE_LIT   1   /* "inout"->3, "out"->2, "in"->1 as literals */
#define RULE_INL   2   /* the same answers from spelled-out byte compares */

/* The whitespace-free body is scanned for the rule's ordered keyword/answer
 * pairs. The window between a keyword and its `return` is bounded by what
 * the copies MEASUREDLY need and no more -- the bound is what stops a
 * function that merely mentions "in" somewhere from carrying the shape.
 *
 * The two windows are measured, not guessed, and the first guess was wrong in
 * a way that made the check report zero carriers and fail red for the wrong
 * reason. Measured distance from a keyword to its `{return <digit>;}`:
 * literal spelling 36..43 bytes (abi 43/39/37, calls 42/38/36, and
 * call_types byte-identical to calls), inlined spelling 39..96 (the 96 is
 * the five-byte test, which spells "inout" as five chained byte compares).
 *
 * The window must therefore be the largest GAP plus the nine bytes the
 * answer itself occupies -- `{return`, the digit, `;` -- because the loop
 * condition is `p + 9 <= lim` and p is the offset of the answer's brace.
 * So 43+9 = 52 and 96+9 = 105, which are the two constants below. An
 * earlier version used 48 and 120: 48 was below the 52 the literal arm
 * needs and so silently dropped the answer, and 120 was needlessly large
 * for the inlined arm. Both numbers here are arithmetic on the measurement
 * above, not round figures. */
static int rule_shape(const char *b, size_t n)
{
  static const char *kw[3] = {"\"inout\"", "\"out\"", "\"in\""};
  static const char ans[3] = {'3', '2', '1'};
  size_t at = 0;
  for (unsigned k = 0; k < 3; k++) {
    const char *hit = NULL;
    for (size_t i = at; i + strlen(kw[k]) <= n; i++)
      if (memcmp(b + i, kw[k], strlen(kw[k])) == 0) { hit = b + i; break; }
    if (!hit) return RULE_NONE;
    /* From the keyword, the FIRST `{` in the window must be the one that
     * opens `{return <digit>;}`: a nested block in between means this keyword
     * is not the one the comparison answers from.
     *
     * The order of the two tests is load-bearing and its inversion was a
     * measured failure, not a reading error: `if (*p=='{') break;` placed
     * BEFORE the `{return` comparison breaks on the very brace that begins the
     * answer it is looking for, so the scan never fired and the check
     * reported zero carriers on a tree that holds four. Match first, then
     * treat any other brace as the end of the window. */
    const char *lim = hit + 52 < b + n ? hit + 52 : b + n;
    int got = 0;
    for (const char *p = hit; p < lim; p++) {
      /* NINE bytes are read: '{','r'..'n' (7), the digit, the ';'. The
       * bound is p+9 <= lim and NOT p+10 <= lim, and the difference is not
       * cosmetic: with 10 the last nine bytes of every window are unreadable,
       * which is exactly where the answer sits. abi.nova answers at offset 43
       * in a 48-byte window, so `p+10 <= lim` failed at p=409 and the scan
       * walked past the answer it was looking for. That is why the check
       * reported zero carriers on a tree holding four. */
      if (p + 9 <= lim && memcmp(p, "{return", 7) == 0 &&
          p[7] == ans[k] && p[8] == ';') { got = 1; break; }
      if (*p == '{') break;
    }
    if (!got) return RULE_NONE;
    at = (size_t)(hit - b) + strlen(kw[k]);
  }
  return RULE_LIT;
}

/* Ownership adds only a suffix to the comparator name. Normalize precisely
 * that call spelling, then retain the existing keyword/answer window. The
 * helper's complete compact body is checked separately at its definition. */
static const char OWNED_COMPARATOR_BODY[] =
  "fnsame_bytes_owned(source:buf<u8>,start:u64,end:u64,text:buf<u8>)->bool{"
  "letresult:bool=same_bytes(source,start,end,text);"
  "rt_free(runtime(),text);returnresult;}";
static int rule_shape_owned(const char *body, size_t n) {
  char normalized[65536];
  size_t at = 0;
  if (n >= sizeof normalized) return RULE_NONE;
  for (size_t i = 0; i < n;) {
    if (i + 17 <= n && memcmp(body + i, "same_bytes_owned(", 17) == 0) {
      memcpy(normalized + at, "same_bytes(", 11);at += 11;i += 17;
    } else normalized[at++] = body[i++];
  }
  normalized[at] = 0;
  return rule_shape(normalized, at);
}

/* The second spelling. x64_lower_nxo.nova has no same_bytes, so it spells the
 * keywords as their bytes: 105 i, 110 n, 116 o, 117 u, 116 t. The shape is
 * the LENGTH DISCRIMINATOR plus the answers, not the bytes themselves: a
 * length test of 5 (only "inout" is five bytes) answering 3, of 3 ("out")
 * answering 2 and of 2 ("in") answering 1. Anchoring on lengths rather than
 * on the byte values is what makes this an arm of the same rule and not a
 * fingerprint of one module. */
static int rule_shape_inlined(const char *b, size_t n)
{
  /* Ordered longest discriminator first. "in" is length two, and its test
   * reads n==2 while "out" reads n==3: matching the shorter test first would
   * let the two-byte test be found before the three-byte one only if the body
   * wrote them out of order, which no copy does -- but the array is written
   * in the RULE's order anyway, so the scan order and the rule order are the
   * same thing and there is no second convention to keep in step.
   * Windows: measured 39, 58 and 96 bytes to the answering `return`, so 120
   * covers the largest with margin. See the measurement above rule_shape. */
  static const struct { const char *len; char ans; } a[3] = {
    {"==5&&", '3'}, {"==3&&", '2'}, {"==2", '1'}
  };
  size_t at = 0;
  /* The four letters must be spelled out, or this arm cannot be telling the
   * keyword from an unrelated byte compare. 105 i, 110 n, 116 o, 117 u. */
  if (!strstr(b, "==105") || !strstr(b, "==110") || !strstr(b, "==116") ||
      !strstr(b, "==117"))
    return RULE_NONE;
  for (unsigned k = 0; k < 3; k++) {
    size_t len = strlen(a[k].len);
    const char *hit = NULL;
    for (size_t i = at; i + len <= n; i++)
      if (memcmp(b + i, a[k].len, len) == 0) { hit = b + i; break; }
    if (!hit) return RULE_NONE;
    const char *lim = hit + 105 < b + n ? hit + 105 : b + n;
    int got = 0;
    /* Same order as rule_shape: match the answer before treating a brace as
     * the end of the window, for the same measured reason. */
    for (const char *p = hit; p < lim; p++) {
      /* Nine bytes, not ten -- see rule_shape. Same arithmetic, same reason. */
      if (p + 9 <= lim && memcmp(p, "{return", 7) == 0 &&
          p[7] == a[k].ans && p[8] == ';') { got = 1; break; }
      if (*p == '{') break;
    }
    if (!got) return RULE_NONE;
    at = (size_t)(hit - b) + len;
  }
  return RULE_INL;
}

/* The driver. It walks the same directory the name scan walks, extracts every
 * TOP LEVEL function body with the whitespace removed, and confronts each
 * body against both rule signatures.
 *
 * The body extraction is the SAME text handling scan_direction_copies already
 * proved on this tree: a definition is what def_name_at reads opening a line
 * with the indentation skipped -- `fn <name>` or `export fn <name>`, since 7
 * October 2026; the 1209 and 58 below were counted when only the first form
 * was read, and the run now prints its own count beside the token reader's --
 * and the body runs to brace depth zero. A `//` comment
 * runs to end of line and is removed before the body is read, so the prose in
 * call_types.nova:21 -- which names all four copies -- can never be counted
 * as code. Both halves of that were measured rather than assumed: brace
 * counting with and without string-literal awareness sees the same 1209
 * top level functions in the same 58 modules and the same four carriers, so
 * the simpler counting is used and the string-literal hazard is recorded as
 * checked rather than as a risk.
 */
static void check_owned_rule_shape_controls(void) {
  static const char fixture[] =
    "letinout_:buf<u8>=\"inout\";ifsame_bytes_owned(source,at,stop,inout_){return3;}"
    "letout_:buf<u8>=\"out\";ifsame_bytes_owned(source,at,stop,out_){return2;}"
    "letin_:buf<u8>=\"in\";ifsame_bytes_owned(source,at,stop,in_){return1;}";
  CHECK(rule_shape_owned(fixture, strlen(fixture)) == RULE_LIT,
        "owned comparator spelling retains the complete direction shape");
  for (unsigned k = 0; k < 3; k++) {
    char mutant[sizeof fixture];memcpy(mutant, fixture, sizeof fixture);
    char answer[] = "{return3;";answer[7] = (char)('3' - k);
    char *hit = strstr(mutant, answer);
    CHECK(hit != NULL, "direction shape mutant locates its selected answer");
    if (hit) {
      hit[7] = '0';
      CHECK(rule_shape_owned(mutant, strlen(mutant)) == RULE_NONE,
            "changing any direction answer rejects the owned shape");
    }
  }
  char keyword_mutant[sizeof fixture];
  memcpy(keyword_mutant, fixture, sizeof fixture);
  char *keyword = strstr(keyword_mutant, "\"inout\"");
  CHECK(keyword != NULL, "direction keyword mutant locates its keyword");
  if (keyword) {
    keyword[1] = 'x';
    CHECK(rule_shape_owned(keyword_mutant, strlen(keyword_mutant)) == RULE_NONE,
          "wrong keyword rejects the owned direction shape");
  }
}

static void scan_direction_rule_shape(void)
{
  check_owned_rule_shape_controls();
  DIR *d = opendir(NOVA_MODULE_DIR);
  checks++;
  if (!d) {
    failures++;
    fprintf(stderr, "FAIL DIRECTION-SHAPE cannot open %s\n", NOVA_MODULE_DIR);
    return;
  }
  unsigned carriers = 0, functions = 0, declared = 0, not_copies = 0;
  unsigned token_defs = 0, unseen_modules = 0;
  struct dirent *e;
  while ((e = readdir(d)) != 0) {
    size_t len = strlen(e->d_name);
    if (len < 6 || strcmp(e->d_name + len - 5, ".nova") != 0) continue;
    if (e->d_name[0] == '.') continue;
    char path[512];
    snprintf(path, sizeof path, "%s/%s", NOVA_MODULE_DIR, e->d_name);
    size_t n = 0;
    char *text = load(path, &n);
    checks++;
    if (!text) {
      failures++;
      fprintf(stderr, "FAIL DIRECTION-SHAPE cannot read %s\n", path);
      continue;
    }
    unsigned line = 1, line_defs = 0;
    for (size_t i = 0; i < n;) {
      size_t j = i;
      while (j < n && text[j] != '\n') j++;
      /* the line with its comment removed */
      size_t code_end = j;
      for (size_t k = i; k < j; k++)
        if (text[k] == '/' && k + 1 < j && text[k + 1] == '/') {
          code_end = k;
          break;
        }
      size_t p = i;
      while (p < code_end && (text[p] == ' ' || text[p] == '\t')) p++;
      size_t from = 0, w = def_name_at(text, p, code_end, &from);
      int is_def = w > 0;
      char name[NAME_CAP] = {0};
      if (is_def) {
        line_defs++;
        if (w < NAME_CAP) memcpy(name, text + from, w);
      }
      if (is_def && name[0]) {
        /* Accumulate the body to brace depth zero, whitespace stripped.
         *
         * `entered` is load-bearing and its absence is a measured failure,
         * not a style choice. The signature line opens with
         *   fn direction(source:buf<u8>,...)->u64 {
         * so depth is ZERO for every character before that `{`. A test of
         * `depth == 0` alone therefore terminates on the second character of
         * the signature and yields the two-byte body "fn" for all 1209
         * functions of the tree. That is what the first run of this check
         * did: it reported zero carriers and failed red for the wrong reason,
         * which is the shape of an instrument that cannot tell a signal from
         * a constant. `entered` says the body has actually begun. */
        static char body[65536];
        size_t bn = 0;
        int depth = 0, entered = 0;
        for (size_t k = i; k < n && bn + 1 < sizeof body;) {
          size_t e2 = k;
          while (e2 < n && text[e2] != '\n') e2++;
          size_t ce = e2;
          for (size_t z = k; z < e2; z++)
            if (text[z] == '/' && z + 1 < e2 && text[z + 1] == '/') {
              ce = z;
              break;
            }
          int line_done = 0;
          for (size_t z = k; z < ce; z++) {
            char ch = text[z];
            if (ch == '{') { depth++; entered = 1; }
            else if (ch == '}') depth--;
            if (ch != ' ' && ch != '\t' && ch != '\n' && ch != '\r')
              body[bn++] = ch;
            if (entered && depth == 0) { line_done = 1; break; }
          }
          if (line_done) break;
          k = e2 + 1;
        }
        body[bn] = 0;
        functions++;
        if (strcmp(e->d_name, "abi.nova") == 0 &&
            strcmp(name, "same_bytes_owned") == 0)
          CHECK(strcmp(body, OWNED_COMPARATOR_BODY) == 0,
                "owned comparator delegates unchanged comparison, frees text, returns result");
        int shape = rule_shape_owned(body, bn);
        if (shape == RULE_NONE) shape = rule_shape_inlined(body, bn);
        const struct named_not_copy *nc = NULL;
        for (unsigned k = 0; k < NOT_COPIES; k++)
          if (strcmp(e->d_name, known_not_copies[k].file) == 0 &&
              strcmp(name, known_not_copies[k].name) == 0)
            nc = &known_not_copies[k];
        if (nc) {
          not_copies++;
          /* The relay half of the declaration, read on the same body the
           * rule is read on: whitespace is gone, so the call is spelled
           * without it. */
          WANT_AT(!nc->relays_to || strstr(body, nc->relays_to),
                  "FAIL DIRECTION-RELAY-BROKEN %s:%u fn %s is declared a relay "
                  "to %s and its body no longer calls it",
                  e->d_name, line, name, nc->relays_to ? nc->relays_to : "-");
        }
        if (shape != RULE_NONE) {
          carriers++;
          int is_declared = 0;
          for (unsigned k = 0; k < KNOWN_COPIES; k++)
            is_declared |= strcmp(e->d_name, known_copies[k].file) == 0 &&
                           strcmp(name, known_copies[k].name) == 0;
          if (is_declared) declared++;
          else {
            failures++;
            checks++;
            fprintf(stderr,
                    "FAIL DIRECTION-SHAPE-EXTRA %s:%u fn %s carries the "
                    "direction rule's shape (spelling %c) and is a fifth "
                    "implementation, owned by abi.nova fn direction%s\n",
                    e->d_name, line, name, shape == RULE_LIT ? 'L' : 'I',
                    nc ? "; it is declared NOT to be a copy, so the "
                         "declaration is false" : "");
          }
        }
      }
      i = j + 1;
      line++;
    }
    /* The two readings of the same module must agree. A definition the line
     * reader cannot see -- one opening mid line, or with its keywords split
     * over lines -- is a count the token reader has and the line reader does
     * not, and it is named here with its module rather than left out of
     * every number below. */
    unsigned tdefs = token_definitions(text, n);
    token_defs += tdefs;
    checks++;
    if (tdefs != line_defs) {
      failures++;
      unseen_modules++;
      fprintf(stderr,
              "FAIL DIRECTION-SHAPE DEFINITION-FORM-UNSEEN %s: the reference "
              "lexer's reading counts %u top level definitions and the line "
              "reader %u; a definition is written in a form neither scan reads\n",
              e->d_name, tdefs, line_defs);
    }
    free(text);
  }
  closedir(d);
  WANT_AT(not_copies == NOT_COPIES,
          "FAIL DIRECTION-SHAPE read %u of the %u declared names that are not "
          "copies", not_copies, NOT_COPIES);
  /* The count that decides whether this instrument is a check or a tautology.
   * It is DERIVED on every run -- every top level function of every module is
   * read and classified -- so it cannot be satisfied by editing a constant. */
  WANT_AT(functions > 1000,
          "FAIL DIRECTION-SHAPE read only %u top level functions, the tree "
          "holds over a thousand", functions);
  WANT_AT(carriers == KNOWN_COPIES,
          "FAIL DIRECTION-SHAPE found %u functions carrying the direction "
          "rule shape, expected %u", carriers, KNOWN_COPIES);
  WANT_AT(declared == KNOWN_COPIES,
          "FAIL DIRECTION-SHAPE matched %u of the %u declared copies by "
          "shape", declared, KNOWN_COPIES);
  checks++;
  fprintf(stderr,
          "DIRECTION-SHAPE n_functions=%u n_token_definitions=%u "
          "n_modules_disagreeing=%u n_carrying_shape=%u "
          "n_declared_matched=%u n_not_copies_read=%u "
          "forms=fn_and_export_fn spelling=literal_and_inlined\n",
          functions, token_defs, unseen_modules, carriers, declared,
          not_copies);
}


/* ===================== W9: the thirteen saved registers ====================
 *
 * codegen.c declares the thirteen GPR families the nx64 frame pushes on entry
 * and can therefore skip restoring on exit. x64_lower_nxo.nova spells the
 * same thirteen in the same order, and the ONLY thing binding the two was a
 * comment. That is the wave 7 failure mode: a symbol named after its source
 * that every gate accepted because it was non-zero and ascending.
 *
 * This scan closes the hole and changes no verdict. It derives the set from
 * the C oracle's own text and confronts both other spellings against it, in
 * order, element by element. It confronts the RULE, not a memorised array:
 * the thirteen must be exactly the sixteen GPR families minus rax, rsp and
 * rbp, because that complement is the form abi.nova's refusal is written in.
 * A check of "these thirteen literals in this order" would pass again the
 * day someone transposed two of them.
 *
 * The exclusion is three families, not two, and only one of the three is a
 * false promise. rax is redundant but true (the frame never restores it, it
 * is the return channel, and shipped modules say so); rsp is inert; rbp is
 * the frame pointer the epilogue itself depends on and cannot skip. Only the
 * third is refused, and that is a claim about a promise, not about a set.
 */
#define CODEGEN_C "compiler/c/ntasm/backend/codegen.c"
#define SAVED_C_ANCHOR "saved_registers[] = {"
#define SAVED_NOVA_FILE NOVA_MODULE_DIR "/x64_lower_nxo.nova"
#define SAVED_NOVA_ANCHOR "fn saved_register(index:u64)->u64 {"
#define SAVED_NOVA_TAIL "return 255;"
#define SAVED_TEST_FILE \
  "tests/c/nova/tests_ntasm_x64_lower_nxo_function_bodies.c"
#define SAVED_TEST_ANCHOR "saved[13] = {"
#define SAVED_CAP 32

/* Digit runs of a brace initializer, starting just after `anchor`. Stops at
 * the closing brace, at a semicolon, or at SAVED_CAP. Returning 0 for a
 * missing anchor is deliberate: a renamed or moved declaration must turn
 * this gate red, never turn it into a scan that found nothing and agreed. */
static unsigned read_saved_list(const char *path, const char *anchor,
                                unsigned *out)
{
  size_t n = 0;
  char *text = load(path, &n);
  if (!text) return 0;
  const char *p = strstr(text, anchor);
  unsigned count = 0;
  if (p) {
    p += strlen(anchor);
    while (*p && *p != '}' && *p != ';' && count < SAVED_CAP) {
      if (*p >= '0' && *p <= '9') {
        char *stop = NULL;
        out[count++] = (unsigned)strtoul(p, &stop, 10);
        p = stop;
      } else {
        p++;
      }
    }
  }
  free(text);
  return count;
}

/* The same thirteen out of the Nova lowering's index-to-family function, in
 * the order its branches are written, which is the order the prologue pushes
 * them. `ordered` reports whether every branch sat at the position its own
 * index names, so a reordered function is caught as an ordering defect and
 * not silently reshuffled into agreement. */
static unsigned read_saved_nova(unsigned *out, int *ordered)
{
  size_t n = 0;
  char *text = load(SAVED_NOVA_FILE, &n);
  if (!text) return 0;
  const char *head = strstr(text, SAVED_NOVA_ANCHOR);
  const char *tail = head ? strstr(head, SAVED_NOVA_TAIL) : NULL;
  unsigned count = 0;
  *ordered = 1;
  if (head && tail) {
    const char *p = head + strlen(SAVED_NOVA_ANCHOR);
    while (p < tail && count < SAVED_CAP) {
      const char *hit = strstr(p, "if index==");
      if (!hit || hit >= tail) break;
      char *stop = NULL;
      unsigned index = (unsigned)strtoul(hit + strlen("if index=="), &stop, 10);
      const char *rp = strstr(stop, "return ");
      if (!rp || rp >= tail) break;
      char *stop2 = NULL;
      unsigned family = (unsigned)strtoul(rp + strlen("return "), &stop2, 10);
      if (index >= SAVED_CAP) { *ordered = 0; break; }
      if (index != count) *ordered = 0;
      out[index] = family;
      if (index + 1 > count) count = index + 1;
      p = stop2;
    }
  }
  free(text);
  return count;
}

/* A derived value, not a literal: count the occurrences of a byte string.
 * Used to pin how many places a rule is written down, so an addition turns
 * this gate red instead of quietly making a second copy. */
static unsigned count_bytes(const char *hay, const char *needle)
{
  size_t n = strlen(needle), at = 0, seen = 0;
  if (!hay || !n) return 0;
  while (hay[at]) {
    if (!strncmp(hay + at, needle, n)) { seen++; at += n; }
    else at++;
  }
  return seen;
}

static void scan_saved_register_copies(void)
{
  unsigned c_set[SAVED_CAP], nova_set[SAVED_CAP], test_set[SAVED_CAP];
  int ordered = 0;
  unsigned c_n = read_saved_list(CODEGEN_C, SAVED_C_ANCHOR, c_set);
  unsigned t_n = read_saved_list(SAVED_TEST_FILE, SAVED_TEST_ANCHOR, test_set);
  unsigned n_n = read_saved_nova(nova_set, &ordered);
  WANT_AT(c_n == 13, "FAIL SAVED-SET codegen.c yielded %u families, expected 13", c_n);
  if (c_n != 13) return;

  /* The rule, derived from the C text and not asserted as a literal array:
   * the thirteen must be the sixteen GPR families 0..15 minus {0,4,5}, which
   * are rax, rsp and rbp in the family numbering codegen.c uses. A duplicate
   * would shrink the set below thirteen and fail here rather than pass. */
  unsigned present[16] = {0}, dup = 0, over = 0, excluded[3] = {0, 4, 5};
  for (unsigned i = 0; i < c_n; i++) {
    if (c_set[i] > 15) { over++; continue; }
    present[c_set[i]]++;
  }
  for (unsigned i = 0; i < 16; i++) dup += present[i] > 1;
  WANT_AT(over == 0, "FAIL SAVED-SET %u entries are not a GPR family 0..15", over);
  WANT_AT(dup == 0, "FAIL SAVED-SET %u families appear twice in codegen.c", dup);
  for (unsigned i = 0; i < 16; i++) {
    int must = 1;
    for (unsigned k = 0; k < 3; k++) if (i == excluded[k]) must = 0;
    WANT_AT((present[i] == 1) == (must != 0),
            "FAIL SAVED-SET family %u is %s but the rule says it %s be in the set",
            i, present[i] == 1 ? "in" : "out", must ? "must" : "must not");
  }

  /* Both other spellings, in order, element by element. */
  WANT_AT(n_n == 13, "FAIL SAVED-SET x64_lower_nxo.nova yielded %u families, expected 13", n_n);
  WANT_AT(ordered, "FAIL SAVED-SET x64_lower_nxo.nova saved_register branches are not at their own index");
  for (unsigned i = 0; i < 13 && i < n_n; i++)
    WANT_AT(nova_set[i] == c_set[i],
            "FAIL SAVED-DRIFT x64_lower_nxo.nova saved_register[%u] is family %u, codegen.c says %u",
            i, nova_set[i], c_set[i]);
  WANT_AT(t_n == 13, "FAIL SAVED-SET function_bodies reference_prologue yielded %u families, expected 13", t_n);
  for (unsigned i = 0; i < 13 && i < t_n; i++)
    WANT_AT(test_set[i] == c_set[i],
            "FAIL SAVED-DRIFT reference_prologue saved[%u] is family %u, codegen.c says %u",
            i, test_set[i], c_set[i]);
}

/* WHICH OF abi.nova's RULES ARE PROFILE-SCOPED. A file that is right about
 * one rule and wrong about another is the shape that let stub_table size a
 * symbol table on a witness code, so the scope is pinned here instead of
 * left to the reader. This is the INVENTORY half; the behavioural half is
 * the profile table above, which asks both layers the same question over a
 * tree carrying each profile and requires them to agree on nx64 and to
 * disagree on efi. An inventory cannot see a rule that is scoped wrongly,
 * only one that is scoped without saying so, and that is the whole of what
 * it is for.
 *
 * There are two profile names and no third. abi.nova reads each of them once
 * per clause, through profile_of, so the counts below are an inventory of
 * the plumbing: a fourth name, or a second way of resolving a declaration's
 * profile, moves one of them.
 *
 * `profile==1` is the count of RULES, and it is the number that matters:
 * 328 reason 1 (the fourteen parameter cap) and 328 reason 2 (the fifth and
 * later parameter must carry a binding). A third scoped rule moves it, and so
 * does a scope quietly dropped from one of these two. What the two refuse
 * under efi is measured by the table and asserted nowhere here.
 *
 * THE NAMES THEMSELVES ARE STILL REFUSED, and that is deliberate and is not
 * this lot's to change: check answers 327 for a profile it does not
 * implement, before parameter_rules runs, so the efi arm of both rules is
 * LATENT. Read a green row of the table as "the rule is right under efi",
 * never as "efi-x64-v0 compiles". It does not, and until the lowering has an
 * efi path it must not: a parseable efi function would pass abi.check, be
 * refused later by x64_lower_nxo with 1328 on a fifth and later unbound
 * parameter, and have been labelled `;abi=nx64-abi-v0;` on the way
 * (x64_lower_nxo.nova:245, an unconditional literal with no profile test
 * anywhere in that module). */
#define ABI_PROFILE_NAME_SITES "is_nx64("
#define ABI_PROFILE_NAME_SITES_N 2 /* definition and call in profile_of; EFI gates now use profile_of */
#define ABI_EFI_NAME "is_efi("
#define ABI_EFI_NAME_SITES_N 2   /* one definition, one call in profile_of */
#define ABI_PROFILE_OF "profile_of("
#define ABI_PROFILE_OF_SITES_N 5 /* definition, declaration, module, and two accepted-profile gates */
#define ABI_DECL_PROFILE "declaration_profile("
#define ABI_DECL_PROFILE_SITES_N 2 /* one definition, one call in the rules */
#define ABI_SCOPED_RULES "profile==1"
#define ABI_SCOPED_RULES_N 2      /* 328 reason 1 and 328 reason 2 */
static void pin_abi_profile_scope(void)
{
  static const struct { const char *what, *kind, *needle; unsigned n; } pins[] = {
    {"is_nx64", "profile name", ABI_PROFILE_NAME_SITES, ABI_PROFILE_NAME_SITES_N},
    {"is_efi", "profile name", ABI_EFI_NAME, ABI_EFI_NAME_SITES_N},
    {"profile_of", "profile plumbing", ABI_PROFILE_OF, ABI_PROFILE_OF_SITES_N},
    {"declaration_profile", "profile plumbing", ABI_DECL_PROFILE,
     ABI_DECL_PROFILE_SITES_N},
    {"profile==1", "profile-scoped rule", ABI_SCOPED_RULES, ABI_SCOPED_RULES_N},
  };
  size_t n = 0;
  char *text = load(NOVA_MODULE_DIR "/abi.nova", &n);
  checks++;
  if (!text) { failures++; fprintf(stderr, "FAIL PROFILE-SCOPE cannot read abi.nova\n"); return; }
  for (unsigned k = 0; k < sizeof pins / sizeof pins[0]; k++) {
    unsigned seen = count_bytes(text, pins[k].needle);
    WANT_AT(seen == pins[k].n,
            "FAIL PROFILE-SCOPE abi.nova has %u %s occurrences of \"%s\", expected %u: a rule became profile-aware, a scope was dropped, or the gate moved",
            seen, pins[k].kind, pins[k].needle, pins[k].n);
  }
  free(text);
}
static char *dup_text(const char *s)
{
  size_t n = strlen(s) + 1;
  char *b = malloc(n);
  if (b) memcpy(b, s, n);
  return b;
}

/* ===================== lot 24: invalidation of facts ====================
 *
 * A fact that has become false must not be carried forward, and an analysis
 * that cannot finish must REFUSE rather than assume. Those are two different
 * obligations and this block is organised as two different sets of rows,
 * because the case that discriminates between a pass and a no-op is neither of
 * them: it is a STALE CREDIT, a caller that overwrites the location its own
 * parameter arrived in and is then credited with the entry fact anyway.
 *
 * WHY THIS GATE AND NOT A NEW ONE. `legacy/tools/coldproof/ngbuild.sh` is not this
 * lot's to edit, and its GATES array is hand-written, so a new
 * `tests_ntasm_invalidation.c` would be an UNREGISTERED_HARNESS and the suite
 * would go red on the registration rather than on the property. The four
 * artifacts this file already builds are the house pattern for "a query needs
 * an entry of its own", and abi.nova is where the new export lives, so the
 * rows belong here on the merits and not only by necessity.
 *
 * ONE ENTRY, TWO ANSWERS. The image compiles invalidation-entry.nova, which
 * answers the QUERY (abi.fact_validity, abi.fact_is_live) and the GATE THAT
 * CONSUMES IT (call_contracts.check) from the same parse of the same source.
 * A gate that asked only the second would pass a stale credit for ever,
 * because a stale credit is a 0 in the proved count and a 0 is what a correct
 * program produces too. The two are asserted on the SAME fixture text, one
 * after the other, and that pairing is the point of the block.
 *
 * out[4] selects: 1 abi.fact_validity, 2 call_contracts.check, 3
 * abi.fact_is_live on the first predicate, 4 one liveness word per predicate
 * from out[7]. out[5] is the call ordinal among the calls in source order and
 * out[6] the set kind (22 requires, 23 ensures).
 */
typedef struct {
    const char *name;
    const char *src;
    uint64_t call_ordinal;
    uint64_t selector;
    uint64_t want_ret;
    uint64_t w[4];
    uint64_t untouched;   /* 1: out[0..3] must still carry the guard */
    uint64_t no_words;    /* 1: this query writes no count of its own */
} inv_row;

/* The callee every caller fact is aimed at. Its `requires { non_null(p) }` is
 * the fact the caller is supposed to be carrying, and the caller's own
 * `requires { non_null(p) }` is the credit under test. */
#define INV_HEAD \
  "module m\ntarget x86_64-nexora-none\nsection .text {\n"
#define INV_WANTS \
  "fn wants(in p:u64 @rcx)->u64\neffects {}\nclobbers {}\n" \
  "requires { non_null(p) } {\nreturn p\n}\n"

/* 1. THE STALE CREDIT. The caller arrives holding rcx, `non_null(p)` is true
 *    on entry, and `mov rcx, 7` destroys the location before the call. The
 *    fact is dropped, and the pipeline refuses the call with its own 326. */
static const char inv_stale_reg[] =
  INV_HEAD INV_WANTS
  "fn caller(in p:u64 @rcx)->u64\neffects {}\nclobbers {rax}\n"
  "requires { non_null(p) } {\nmov rcx, 7\ncall wants(p)\n"
  "mov rax, 0\nreturn rax\n}\n}\n";
/* 2. THE CONTROL. Same signature, same contract, same call; the only
 *    difference is the write, which is absent. This is what says the drop in
 *    row 1 was the write's doing and not the rule refusing everything. */
static const char inv_live[] =
  INV_HEAD INV_WANTS
  "fn caller(in p:u64 @rcx)->u64\neffects {}\nclobbers {rax}\n"
  "requires { non_null(p) } {\nmov rax, p\ncall wants(p)\n"
  "return rax\n}\n}\n";
/* 3. THE WRITE IS AFTER THE CALL. `writes_parameter` finds this `mov rcx, 7`
 *    -- the whole-body existential DOES see it -- and the fact is still live
 *    at the call, because nothing had destroyed it yet. This row is the one
 *    that separates a WALK from an EXISTENCE, and it is the row a rule
 *    written as "the body writes the location somewhere" gets wrong. */
static const char inv_write_after[] =
  INV_HEAD INV_WANTS
  "fn caller(in p:u64 @rcx)->u64\neffects {}\nclobbers {rax}\n"
  "requires { non_null(p) } {\ncall wants(p)\nmov rcx, 7\n"
  "mov rax, 0\nreturn rax\n}\n}\n";
/* 4. THE SAME WRITE SPELLED BY THE VARIABLE. A location has two names in the
 *    source and a body may use either, so the two spellings must invalidate
 *    alike. Cutting one of the two comparisons is a real hole and the red
 *    proof below cuts it. */
static const char inv_stale_name[] =
  INV_HEAD INV_WANTS
  "fn caller(in p:u64 @rcx)->u64\neffects {}\nclobbers {rax}\n"
  "requires { non_null(p) } {\nmov p, 7\ncall wants(p)\n"
  "mov rax, 0\nreturn rax\n}\n}\n";
/* 5. INTERPROCEDURAL, AND THE CALLEE REALLY WRITES IT. */
static const char inv_stale_callee[] =
  INV_HEAD
  "fn noisy()->u64\neffects {changes_flags}\nclobbers {rcx,rax} {\n"
  "mov rcx, 3\nmov rax, 0\nreturn rax\n}\n" INV_WANTS
  "fn caller(in p:u64 @rcx)->u64\neffects {changes_flags}\nclobbers {rax}\n"
  "requires { non_null(p) } {\ncall noisy()\ncall wants(p)\n"
  "mov rax, 0\nreturn rax\n}\n}\n";
/* 6. The same chain with a callee that touches something else. The descent
 *    reached a body and read it; it did not refuse on sight. */
static const char inv_live_callee[] =
  INV_HEAD
  "fn quiet()->u64\neffects {}\nclobbers {rax} {\nmov rax, 0\nreturn rax\n}\n"
  INV_WANTS
  "fn caller(in p:u64 @rcx)->u64\neffects {}\nclobbers {rax}\n"
  "requires { non_null(p) } {\ncall quiet()\ncall wants(p)\n"
  "return rax\n}\n}\n";
/* 7. MUTUAL RECURSION. top calls ping and then wants; ping calls pong and pong
 *    calls ping, so the walk from top's SECOND call enters ping -> pong -> ping
 *    and never ends. The call under proof is top's SECOND one on purpose: a
 *    cycle is only ENTERED by a call that runs BEFORE the observation point, so
 *    asking about top's first call would walk an empty prefix, answer live, and
 *    prove nothing at all. The
 *    answer is 367 and NOTHING is written: a walk that hit a cycle cannot say
 *    which facts it had already cleared, and half of them is a summary that
 *    is right for the acyclic case and silently wrong for this one. */
static const char inv_recursion[] =
  INV_HEAD INV_WANTS
  "fn top(in p:u64 @rcx)->u64\neffects {}\nclobbers {rax}\n"
  "requires { non_null(p) } {\ncall ping(p)\ncall wants(p)\nreturn rax\n}\n"
  "fn ping(in p:u64 @rcx)->u64\neffects {}\nclobbers {rax}\n"
  "requires { non_null(p) } {\ncall pong(p)\nreturn rax\n}\n"
  "fn pong(in p:u64 @rcx)->u64\neffects {}\nclobbers {rax}\n"
  "requires { non_null(p) } {\ncall ping(p)\nreturn rax\n}\n"
  "}\n";
/* 8. AN IMPORT is a callee with no body in this tree, which is not an empty
 *    body. The walk refuses rather than descending into nothing. */
static const char inv_import[] =
  "module m\ntarget x86_64-nexora-none\n"
  "import a.ext as ext: fn()->u64\neffects {}\nclobbers {}\n"
  "section .text {\n" INV_WANTS
  "fn caller(in p:u64 @rcx)->u64\neffects {}\nclobbers {rax}\n"
  "requires { non_null(p) } {\ncall ext()\ncall wants(p)\n"
  "mov rax, 0\nreturn rax\n}\n}\n";

static const inv_row inv_rows[] = {
  {"stale-register-write",   inv_stale_reg,     0, 1, 0,   {1, 1, 0, 0}, 0, 0},
  {"live-no-write",          inv_live,          0, 1, 0,   {1, 0, 1, 0}, 0, 0},
  {"write-after-call-live",  inv_write_after,   0, 1, 0,   {1, 0, 1, 0}, 0, 0},
  {"stale-variable-write",   inv_stale_name,    0, 1, 0,   {1, 1, 0, 0}, 0, 0},
  {"stale-through-callee",   inv_stale_callee,  1, 1, 0,   {1, 1, 0, 0}, 0, 0},
  {"live-through-callee",    inv_live_callee,   1, 1, 0,   {1, 0, 1, 0}, 0, 0},
  {"recursion-refused",      inv_recursion,     1, 1, 367, {0, 0, 0, 0}, 1, 0},
  {"import-refused",         inv_import,        1, 1, 367, {0, 0, 0, 0}, 1, 0},
  {"is_live-stale",          inv_stale_reg,     0, 3, 0,   {0, 0, 0, 0}, 1, 0},
  {"is_live-live",           inv_live,          0, 3, 1,   {0, 0, 0, 0}, 1, 0},
  {"pipeline-stale-credit",  inv_stale_reg,     0, 2, 326, {0, 0, 0, 0}, 0, 1},
  {"pipeline-live-credit",   inv_live,          0, 2, 0,   {0, 0, 0, 0}, 0, 1},
  {"pipeline-write-after",   inv_write_after,   0, 2, 0,   {0, 0, 0, 0}, 0, 1},
  {"pipeline-recursion",     inv_recursion,     1, 2, 326, {0, 0, 0, 0}, 0, 1},
  {"pipeline-import",        inv_import,        1, 2, 326, {0, 0, 0, 0}, 0, 1},
};

#define INV_ROWS (sizeof inv_rows / sizeof inv_rows[0])

/* One query, five words of answer: the code and the four words the entry is
 * allowed to write on a decided answer. A refusal writes none of them, which
 * is asserted by comparing them with the guard rather than by reading a flag
 * the entry could have set. */
typedef struct { uint64_t ret, rt, w[4]; } inv_ans;

static inv_ans inv_query(const NovaHostImage *i, const inv_row *r)
{
    Run o = run_mode(i, r->src, 24, r->selector, r->call_ordinal, 0);
    inv_ans a; unsigned k;
    a.ret = o.returned; a.rt = o.runtime;
    for (k = 0; k < 4; k++) a.w[k] = o.out[k];
    return a;
}

static void inv_case(const NovaHostImage *i, const inv_row *r)
{
    inv_ans a;
    const char *why = NULL;
    unsigned k;
    cases++;
    a = inv_query(i, r);
    if (a.ret != r->want_ret) { checks++; failures++;
        fprintf(stderr, "FAIL invalidation %s: ret=%llu want=%llu\n",
                r->name, (unsigned long long)a.ret,
                (unsigned long long)r->want_ret);
        return; }
    if (r->no_words) {
        /* Selector 2 hands out[0..3] to call_contracts.check and selector 3
         * answers in its RETURN value, so neither writes a count of its own and
         * asserting four words on those rows would be asserting the layout this
         * file wished for rather than the one the export publishes. The code is
         * the whole claim on them. */
        checks++;
        return;
    }
    if (r->untouched) {
        for (k = 0; k < 4; k++)
            if (a.w[k] != guard) { checks++; failures++;
                fprintf(stderr, "FAIL invalidation %s: a refusal wrote out[%u]=%llu\n",
                        r->name, k, (unsigned long long)a.w[k]);
                return; }
        checks++;
        return;
    }
    for (k = 0; k < 4; k++)
        if (a.w[k] != r->w[k]) { why = "count word"; break; }
    checks++;
    if (why) {
        failures++;
        fprintf(stderr, "FAIL invalidation %s: %s ret=%llu", r->name, why,
                (unsigned long long)a.ret);
        for (k = 0; k < 4; k++) fprintf(stderr, " out[%u]=%llu", k,
            (unsigned long long)a.w[k]);
        fprintf(stderr, "\n");
    }
}

/* ===================== the red proof ====================
 *
 * A perturbation that cuts ONE site of eleven proves one site of eleven, and
 * a proof that reports green because four other sites still carry the rule is
 * worse than no proof: it says the rule is load-bearing when it removed
 * nothing that was holding it up. So every site the rule reads is cut, one at
 * a time, and the COUNT OF VERDICTS THAT MOVED is printed for each. A site
 * whose count does not move prints PROOF_INVALID and is a failure of the
 * PROOF, not a pass of the rule.
 *
 * THE ANCHORS ARE ASSERTED PRESENT BEFORE ANY SUBSTITUTION, and each must
 * occur EXACTLY ONCE. That is the derivation check: the list is quoted from
 * the rule, so a rule that moves renames the anchor, the anchor is gone, and
 * the proof reports that it can no longer see the site rather than quietly
 * perturbing nothing and reporting a green.
 *
 * THE PERTURBED TEXT IS FED TO THE COMPILER, NOT WRITTEN TO DISK. The
 * compiler takes its sources as (name, text, length), so a perturbed copy of
 * abi.nova is a buffer, and no shared file is ever modified while five sibling
 * lots are running against the same tree.
 *
 * THE ANCHORS ARE SPELLED THE WAY THE RULE SPELLS THEM TODAY. Four of them --
 * A2, A5, A6 and A8 -- quoted a field access (`n.kind`, `n.end`,
 * `ntasm_ast.node_at(tree,x).kind`) and the AST getter migration replaced those
 * accesses with the scalar accessors, so the anchors were gone and those four
 * sites reported PROOF_INVALID rather than perturbing anything: a proof that
 * removes nothing reads exactly like a proof that the rule is load-bearing.
 * They are re-quoted FROM the rule, not re-invented: each still cuts the same
 * statement of the same function, and every replacement is unchanged.
 */
typedef struct {
    const char *id;
    const char *file;      /* "abi" or "call_contracts" */
    const char *anchor;
    const char *repl;
} inv_site;

static const inv_site inv_sites[] = {
  {"A1-mnemonic-classification", "abi",
   "    if is_mov==false && is_store==false { return false; }",
   "    if true { return false; }"},
  {"A2-destination-operand", "abi",
   "    let mnemonic:u64=name_id;\n"
   "    let dest_id:u64=child(tree,id,1);",
   "    let mnemonic:u64=name_id;\n"
   "    let dest_id:u64=child(tree,id,2);"},
  {"A3-register-family-compare", "abi",
   "        if register_widths.family(source,dest.start,dest.end)==family {",
   "        if false {"},
  {"A4-variable-name-compare", "abi",
   "    if same_span(source,dest,name) { return true; }",
   "    if false { return true; }"},
  {"A5-observation-point-order", "abi",
   "            let past:bool=before==0 || ntasm_ast.node_end(tree,n)<=before;",
   "            let past:bool=true;"},
  {"A6-call-node-classification", "abi",
   "                if ntasm_ast.node_kind(tree,n)==28 || (ntasm_ast.node_kind(tree,n)==35 && ntasm_ast.node_aux(tree,n)==1) {",
   "                if false {"},
  {"A7-callee-resolution", "abi",
   "                    let callee:u64=callee_of(source,tree,id);",
   "                    let callee:u64=0;"},
  {"A8-import-has-no-body", "abi",
   "                    if ntasm_ast.node_kind(tree,callee)!=18 { return 2; }",
   "                    if false { return 2; }"},
  {"A9-depth-bound-refuses", "abi",
   "                    if depth==0 { return 2; }",
   "                    if depth==0 { return 0; }"},
  {"A10-effective-register-family", "abi",
   "                            source,tree,caller_id,scratch[0],arg_name,at,depth);",
   "                            source,tree,caller_id,0,arg_name,at,depth);"},
  {"A11-credit-site", "call_contracts",
   "            if abi.fact_is_live(source,tree,caller_id,call_id,pred_id)!=1 {",
   "            if false {"},
};

/* One replacement, refused unless the anchor occurs exactly once. Returning
 * NULL is the refusal, and a refusal here is PROOF_INVALID rather than a
 * silent no-op, because a substitution that matched nothing would leave the
 * rule intact and the count at its base value -- a green that removed
 * nothing. */
static char *inv_perturb(const char *text, const inv_site *s, int *ok)
{
    const char *p = strstr(text, s->anchor);
    size_t head;
    char *out;
    *ok = 0;
    if (!p) return NULL;
    if (strstr(p + strlen(s->anchor), s->anchor)) return NULL;
    head = (size_t)(p - text);
    out = malloc(strlen(text) - strlen(s->anchor) + strlen(s->repl) + 1);
    if (!out) return NULL;
    memcpy(out, text, head);
    memcpy(out + head, s->repl, strlen(s->repl));
    strcpy(out + head + strlen(s->repl), p + strlen(s->anchor));
    *ok = 1;
    return out;
}

/* The battery the red proof measures: every row above, read as the tuple
 * (code, out[0..3]). Two runs that agree on all of them agree on everything
 * this block asserts, so "the count did not move" is a statement about the
 * block and not about a sample. */
static unsigned inv_battery_moved(const NovaHostImage *i,
                                  const inv_ans *base, unsigned n)
{
    unsigned moved = 0, k, b;
    for (k = 0; k < n; k++) {
        inv_ans a = inv_query(i, &inv_rows[k]);
        int same = (a.ret == base[k].ret && a.rt == base[k].rt);
        for (b = 0; b < 4; b++) same = same && (a.w[b] == base[k].w[b]);
        if (!same) moved++;
    }
    return moved;
}

/* The base is measured, not assumed: the battery is run against the
 * UNPERTURBED image first and the count it reports is the "before". A proof
 * that printed a count without a before would let a battery that exercises
 * nothing report 0 moved for all eleven sites and call it a pass. */
static void inv_red_proof(const char *p4[], unsigned n4, const char **s4)
{
    inv_ans base[sizeof inv_rows / sizeof inv_rows[0]];
    unsigned n = (unsigned)(sizeof inv_rows / sizeof inv_rows[0]);
    unsigned base_ok = 0, si, k;
    unsigned before_ok = 0, before_bad = 0;
    int pert_ok = 0;
    NovaHostImage img = {0};
    char *abi_text = NULL, *cc_text = NULL;
    size_t z = 0;

    abi_text = load("compiler/nova/analysis/abi/abi.nova", &z);
    cc_text = load("compiler/nova/analysis/calls/call_contracts.nova", &z);
    checks++;
    if (!abi_text || !cc_text) { failures++;
        fprintf(stderr, "FAIL red-proof: the rule's own sources did not load\n");
        free(abi_text); free(cc_text); return; }

    /* the before, on an image built from the same list with nothing cut */
    {
        NtFInput in[32]; NtArtifact art = {0};
        int ok = 1;
        for (k = 0; k < n4; k++) in[k] = (NtFInput){p4[k], s4[k], (uint64_t)strlen(s4[k])};
        if (!nova_compile_many_v2(in, n4, &art)) ok = 0;
        else if (!nova_host_map(&art, &img)) ok = 0;
        checks++;
        if (!ok) { failures++;
            fprintf(stderr, "FAIL red-proof: the unperturbed battery image did not build\n");
            if (art.error.code) fprintf(stderr, "E%u %llu:%llu %s\n", art.error.code,
                (unsigned long long)art.error.line, (unsigned long long)art.error.column,
                art.error.message);
            nt_artifact_free(&art); free(abi_text); free(cc_text); return; }
        for (k = 0; k < n; k++) base[k] = inv_query(&img, &inv_rows[k]);
        base_ok = 1;
        nt_artifact_free(&art);
    }
    /* The battery is only a battery if it agrees with the rows it is drawn
     * from; a base that already contradicts the table would make every
     * perturbation look like it moved something. */
    for (k = 0; k < n; k++) {
        int same = base[k].ret == inv_rows[k].want_ret && base[k].rt == 0;
        unsigned b;
        /* The same two exemptions inv_case applies, or the cross-check would
         * hold the battery to a layout the query never published. */
        if (!inv_rows[k].no_words) {
            for (b = 0; b < 4; b++)
                same = same && (inv_rows[k].untouched ? base[k].w[b] == guard
                                                      : base[k].w[b] == inv_rows[k].w[b]);
        }
        checks++;
        if (!same) { failures++; before_bad++;
            fprintf(stderr, "FAIL red-proof: the battery disagrees with row %s "
                    "before any perturbation, so its counts would mean nothing\n",
                    inv_rows[k].name); }
        else before_ok++;
    }
    /* The word=value shape is not decoration: ngbuild.sh re-emits a run log
     * through `grep -aE '^[A-Z][A-Z0-9_.-]+ +[a-z_]+='`, so a banner whose
     * second word is a bare name is FILTERED OUT of the stream a watching
     * reader sees, and the count the proof exists to publish would be the one
     * line nobody reads. */
    printf("RED_PROOF battery_rows=%u agreeing_before=%u disagreeing_before=%u\n",
           n, before_ok, before_bad);
    if (!base_ok) { free(abi_text); free(cc_text); return; }

    for (si = 0; si < sizeof inv_sites / sizeof inv_sites[0]; si++) {
        const inv_site *s = &inv_sites[si];
        const char *src = (strcmp(s->file, "abi") == 0) ? abi_text : cc_text;
        char *cut = inv_perturb(src, s, &pert_ok);
        NtFInput in[32]; NtArtifact art = {0};
        const char *swap = NULL; int ok = 1; unsigned moved = 0; unsigned idx = 0;
        if (!cut) {
            printf("RED_PROOF site=%s PROOF_INVALID anchor_absent_or_ambiguous "
                   "file=%s\n", s->id, s->file);
            failures++; checks++;
            continue;
        }
        {
            /* The site names a MODULE, so the path is rebuilt from it rather
             * than matched by substring: a substring test would let "abi" also
             * match any path that merely contains those three letters, and the
             * perturbation would land in a file the rule does not read. */
            char target[256];
            snprintf(target, sizeof target, "compiler/nova/%s.nova", s->file);
            for (k = 0; k < n4; k++) {
                in[k] = (NtFInput){p4[k], s4[k], (uint64_t)strlen(s4[k])};
                if (strcmp(p4[k], target) == 0) {
                    swap = s4[k];
                    in[k] = (NtFInput){p4[k], cut, (uint64_t)strlen(cut)};
                    idx = k;
                }
            }
        }
        if (swap == NULL) { failures++; checks++;
            fprintf(stderr, "FAIL red-proof: site %s names a file the battery "
                    "image does not carry\n", s->id);
            free(cut); continue; }
        if (!nova_compile_many_v2(in, n4, &art)) ok = 0;
        else if (!nova_host_map(&art, &img)) ok = 0;
        if (!ok) {
            printf("RED_PROOF site=%-32s moved_after=0 PROOF_INVALID the "
                   "perturbation did not compile, so it removed nothing\n", s->id);
            if (art.error.code) fprintf(stderr, "E%u %llu:%llu %s\n", art.error.code,
                (unsigned long long)art.error.line, (unsigned long long)art.error.column,
                art.error.message);
            failures++; checks++;
        } else {
            moved = inv_battery_moved(&img, base, n);
            printf("RED_PROOF site=%-32s battery=%u moved_after=%u%s\n",
                   s->id, n, moved, moved ? "" : " PROOF_INVALID");
            checks++;
            if (moved == 0) { failures++;
                fprintf(stderr, "FAIL red-proof: cutting %s moved no verdict, so "
                        "nothing was removed that was carrying the rule\n", s->id); }
            nova_host_unmap(&img);
        }
        (void)idx;
        nt_artifact_free(&art);
        free(cut);
    }
    free(abi_text); free(cc_text);
}

int main(void){const char*paths[]={"tests/nova/tests/abi-entry.nova","compiler/nova/analysis/abi/abi.nova","compiler/nova/analysis/abi/clobbers.nova","compiler/nova/analysis/types/register_widths.nova","compiler/nova/frontend/register_bindings.nova","compiler/nova/frontend/parameters.nova","compiler/nova/analysis/calls/callable_names.nova","compiler/nova/analysis/semantics.nova","compiler/nova/frontend/parser.nova","compiler/nova/frontend/ast.nova","compiler/nova/frontend/lexer.nova"};char*sources[11]={0};NtFInput inputs[11];for(unsigned i=0;i<11;i++){size_t n=0;sources[i]=load(paths[i],&n);inputs[i]=(NtFInput){paths[i],sources[i],n};}int all=1;for(unsigned i=0;i<11;i++)if(!sources[i])all=0;CHECK(all,"sources load");NtArtifact a={0};int compiled=all&&nova_compile_many_v2(inputs,11,&a);CHECK(compiled,"modules compile");if(!compiled)fprintf(stderr,"E%u %zu:%zu %s\n",a.error.code,a.error.line,a.error.column,a.error.message);NovaHostImage image={0};CHECK(compiled&&nova_host_map(&a,&image),"image maps");if(image.memory){
const char*implicit="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in a:u64,in b:u64,in c:u64,in d:u64)->u64\neffects {}\nclobbers {} {\nreturn a\n}\n}\n";ok(&image,"implicit",implicit,1,0,4);
const char*explicit_="module m\ntarget x86_64-nexora-none\ndefault_abi nx64-abi-v0\nsection .text {\nfn f()->u64\nabi nx64-abi-v0\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";ok(&image,"explicit",explicit_,1,0,0);
const char*bad_default="module m\ntarget x86_64-nexora-none\ndefault_abi alien-abi\nsection .text {\nfn f()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";err(&image,"default",bad_default,4,327,1,0,0);
const char*bad_explicit="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\nabi alien-abi\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";err(&image,"explicit bad",bad_explicit,4,327,2,0,0);
const char*fifteen="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in a:u64 @rcx,in b:u64 @rdx,in c:u64 @r8,in d:u64 @r9,in e:u64 @rax,in f:u64 @rbx,in g:u64 @rsi,in h:u64 @rdi,in i:u64 @r10,in j:u64 @r11,in k:u64 @r12,in l:u64 @r13,in m:u64 @r14,in n:u64 @r15,in o:u64 @rbp)->u64\neffects {}\nclobbers {} {\nreturn a\n}\n}\n";err(&image,"fifteen",fifteen,4,328,1,14,0);
const char*fifth="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in a:u64,in b:u64,in c:u64,in d:u64,in e:u64)->u64\neffects {}\nclobbers {} {\nreturn a\n}\n}\n";err(&image,"fifth",fifth,4,328,2,4,0);
const char*out_unbound="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(out a:u64)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";err(&image,"out",out_unbound,4,328,3,0,0);
const char*inout_unbound="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(inout a:u64)->u64\neffects {}\nclobbers {} {\nreturn a\n}\n}\n";err(&image,"inout",inout_unbound,4,328,3,0,0);
const char*out_bool="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(out a:bool @al)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";err(&image,"bool",out_bool,4,329,1,0,0);
const char*pointer_bad="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:ptr<user,u64> @edi)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";err(&image,"ptr32",pointer_bad,4,329,2,0,0);
const char*pointer_ok="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in p:ptr<user,u64> @rdi)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";ok(&image,"ptr64",pointer_ok,1,0,1);
const char*unknown_reg="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in a:u64 @foo)->u64\neffects {}\nclobbers {} {\nreturn a\n}\n}\n";err(&image,"reg",unknown_reg,4,328,4,0,0);
const char*imported="module m\ntarget x86_64-nexora-none\nimport a.f as f: fn(in p:ptr<user,u64> @rdi)->u64\nabi nx64-abi-v0\neffects {}\nclobbers {}\n";ok(&image,"import",imported,0,1,1);
const char*out_ok="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(out a:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn a\n}\n}\n";ok(&image,"out ok",out_ok,1,0,1);const char*out_reserved="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(out a:u64 @rax)->u64\neffects {}\nclobbers {} {\nreturn a\n}\n}\n";err(&image,"out reserved",out_reserved,4,328,5,0,0);const char*out_overlap="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(out a:u64 @rcx)->u64\neffects {}\nclobbers {ecx} {\nreturn a\n}\n}\n";err(&image,"out clobber",out_overlap,4,328,6,0,0);err(&image,"short",implicit,3,800,0,0,1);err(&image,"invalid","target x86_64-nexora-none\n",4,800,0,0,1);
/* CLOBBER DECLARATION CONFORMANCE: EVERY ONE OF THE SIXTEEN IS ACCEPTED.
 *
 * These cases exist to pin this file to the C oracle, and they all assert
 * ACCEPT for the same reason. The oracle accepts a clobbers set naming any of
 * the sixteen families, with zero diagnostics, and the product must agree:
 * a refusal here that the reference does not make is a language change nobody
 * asked for, and the case below is what catches it.
 *
 * WHY rbp AND rsp ARE IN THIS LIST RATHER THAN OUTSIDE IT. An earlier revision
 * of this gate refused rbp as 328 reason 8, on the argument that the epilogue
 * cannot keep the promise. That was wrong, and the oracle's own behaviour says
 * so twice over.
 *
 * The rule is on the WRITE, and it is general. Measured across forms, every
 * destination write to rbp or rsp is refused by the frontend with 503 and the
 * oracle's own words, "requires unavailable stack/frame balance proof": mov
 * (direct and register), add, xor, pop, lea and inc all refuse, for rbp and
 * rsp alike, while the same writes to an ordinary callee-saved register draw
 * only the normal 501 and 502 accounting. The reference protects the frame
 * register on every attempt to write it and leaves the declaration free.
 *
 * And a declaration of rbp is not a false promise. A function that genuinely
 * does not restore rbp is describing itself accurately. Two fixtures in this
 * tree already depend on that: tests_ntasm_body_clobbers.c:253 declares
 * clobbers {rsp,rbp} on a body refused because `leave` writes the frame
 * registers, and tests_ntasm_x64_lower_nxo_function_bodies.c:2180 declares
 * clobbers {rsi,rdi,rbp,rsp} on a body that writes nothing and is accepted.
 * The first is a witness FOR the write rule; the second would have been made
 * red by a declaration rule, and that is how this gate would have caught one.
 *
 * Both of those shapes are pinned here, so the two latent fixtures have a
 * home in the gate that would reject a declaration rule. rsi is included
 * because it is one of the eight the oracle's efi profile treats as
 * nonvolatile, and so is the family the two conventions most disagree on.
 * r12 and r15 pin the far end, so a table that stopped early cannot pass. */
const char*cl_rbp="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rbp} {\nreturn 0\n}\n}\n";ok(&image,"rbp declaration accepted",cl_rbp,1,0,0);
const char*cl_rbp_alias="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {ebp} {\nreturn 0\n}\n}\n";ok(&image,"rbp accepted via ebp alias",cl_rbp_alias,1,0,0);
const char*cl_rbp_mixed="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rcx,rbp} {\nreturn 0\n}\n}\n";ok(&image,"rbp accepted inside a legal set",cl_rbp_mixed,1,0,0);
const char*cl_rbp_rsp="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rsp,rbp} {\nreturn 0\n}\n}\n";ok(&image,"rsp rbp accepted together",cl_rbp_rsp,1,0,0);
const char*cl_latent="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rsi,rdi,rbp,rsp} {\nreturn 0\n}\n}\n";ok(&image,"latent function_bodies shape accepted",cl_latent,1,0,0);
const char*cl_rbp_import="module m\ntarget x86_64-nexora-none\nimport a.f as f: fn()->u64\nabi nx64-abi-v0\neffects {}\nclobbers {rbp}\n";ok(&image,"rbp accepted on an import",cl_rbp_import,0,1,0);
const char*cl_rsp="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rsp} {\nreturn 0\n}\n}\n";ok(&image,"rsp accepted",cl_rsp,1,0,0);
const char*cl_rax="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rax} {\nreturn 0\n}\n}\n";ok(&image,"rax accepted",cl_rax,1,0,0);
const char*cl_rbx="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rbx} {\nreturn 0\n}\n}\n";ok(&image,"rbx accepted",cl_rbx,1,0,0);
const char*cl_rcx="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rcx,rdx} {\nreturn 0\n}\n}\n";ok(&image,"rcx rdx accepted",cl_rcx,1,0,0);
const char*cl_rsi="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {rsi} {\nreturn 0\n}\n}\n";ok(&image,"rsi accepted",cl_rsi,1,0,0);
const char*cl_r12="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {r12} {\nreturn 0\n}\n}\n";ok(&image,"r12 accepted",cl_r12,1,0,0);
const char*cl_r15="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f()->u64\neffects {}\nclobbers {r15} {\nreturn 0\n}\n}\n";ok(&image,"r15 accepted",cl_r15,1,0,0);
/* nx64-abi-v0 default argument register assignment. The spec gives rcx, rdx,
 * r8 then r9 to the first four unbound in-parameters; no case below may rely
 * on a register the spec does not name. */
const char*free4="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in a:u64,in b:u64,in c:u64,in d:u64)->u64\neffects {}\nclobbers {} {\nreturn a\n}\n}\n";
qarg(&image,"free4 p0 rcx",free4,0,0,1,2,0,1);
qarg(&image,"free4 p1 rdx",free4,0,1,2,3,0,1);
qarg(&image,"free4 p2 r8",free4,0,2,8,9,0,1);
qarg(&image,"free4 p3 r9",free4,0,3,9,10,0,1);
const char*imp2="module m\ntarget x86_64-nexora-none\nimport a.f as f: fn(in p:u64,in q:u64 @rdx)->u64\nabi nx64-abi-v0\neffects {}\nclobbers {}\n";
qarg(&image,"import p0 rcx",imp2,0,0,1,2,0,1);
qarg(&image,"import p1 bound rdx",imp2,0,1,0,0,3,1);
const char*shift="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in a:u64 @rbx,in b:u64,in c:u64,in d:u64)->u64\neffects {}\nclobbers {} {\nreturn a\n}\n}\n";
qarg(&image,"shift p0 bound",shift,0,0,0,0,4,1);
qarg(&image,"shift p1 rdx",shift,0,1,2,3,0,1);
qarg(&image,"shift p3 r9",shift,0,3,9,10,0,1);
const char*outclean="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(out a:u64 @r10,in b:u64,in c:u64,in d:u64)->u64\neffects {}\nclobbers {} {\nreturn b\n}\n}\n";
qarg(&image,"out consumes nothing",outclean,0,0,0,0,11,0);
qarg(&image,"out keeps raw ordinal",outclean,0,1,2,3,0,1);
qarg(&image,"out keeps ordinal 2",outclean,0,2,8,9,0,1);
qarg(&image,"out keeps ordinal 3",outclean,0,3,9,10,0,1);
qarg(&image,"free4 p4 past table",free4,0,4,0,0,0,0);
qarg_800(&image,"free4 missing declaration",free4,9,0);
legacy_sealed(&image,"legacy four words",free4,4,1,0,4);
/* Default-versus-explicit collision on one physical family. */
const char*hit1="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in a:u64,in b:u64 @rcx)->u64\neffects {}\nclobbers {} {\nreturn a\n}\n}\n";
err(&image,"collision p1 rcx",hit1,4,328,7,1,0);
qarg_sealed(&image,"collision seals query",hit1,328,7,1);
const char*hit2="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in a:u64 @r9,in b:u64 @rcx,in c:u64,in d:u64)->u64\neffects {}\nclobbers {} {\nreturn a\n}\n}\n";
err(&image,"collision p3 r9",hit2,4,328,7,3,0);
const char*hit3="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in a:u64 @r8,in b:u64 @rdx,in c:u64)->u64\neffects {}\nclobbers {} {\nreturn a\n}\n}\n";
err(&image,"collision p2 r8",hit3,4,328,7,2,0);
const char*hit4="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in a:u32,in b:u32 @ecx)->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";
err(&image,"collision alias ecx",hit4,4,328,7,1,0);
err(&image,"collision out family","module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(out a:u64 @rdx,in b:u64,in c:u64,in d:u64)->u64\neffects {}\nclobbers {} {\nreturn b\n}\n}\n",4,328,7,1,0);
const char*hit5="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in a:u64,in b:u64,in c:u64,in d:u64 @rcx,in e:u64 @rax)->u64\neffects {}\nclobbers {} {\nreturn a\n}\n}\n";
err(&image,"collision p3 rcx",hit5,4,328,7,3,0);
/* Negative: a parameter bound to the register it would have received by
 * default is a no-op, not a collision. */
const char*bound4="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in a:u64 @rcx,in b:u64 @rdx,in c:u64 @r8,in d:u64 @r9)->u64\neffects {}\nclobbers {} {\nreturn a\n}\n}\n";
ok(&image,"bound to default",bound4,1,0,4);
const char*mixed="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in a:u64 @r9,out b:u64 @rbx)->u64\neffects {}\nclobbers {} {\nreturn a\n}\n}\n";
ok(&image,"no default beside bound",mixed,1,0,2);
const char*clean5="module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(in a:u64 @rax,in b:u64 @rbx,in c:u64,in d:u64 @r10,in e:u64 @r11)->u64\neffects {}\nclobbers {} {\nreturn c\n}\n}\n";
ok(&image,"one default among bounds",clean5,1,0,5);
coll(&image,"free4 clean",free4,0,0,0,0,0,1,4);
coll(&image,"bound4 clean",bound4,0,0,0,0,0,1,4);
coll(&image,"shift clean",shift,0,0,0,0,0,1,4);
coll(&image,"outclean clean",outclean,0,0,0,0,0,1,4);
coll(&image,"mixed clean",mixed,0,0,0,0,0,1,2);
coll(&image,"clean5 clean",clean5,0,0,0,0,0,1,5);
coll(&image,"import clean",imp2,0,0,0,0,0,1,2);
coll(&image,"hit1 reports",hit1,328,7,1,4,25,0,0);
coll(&image,"hit2 reports",hit2,328,7,3,4,42,0,0);
coll(&image,"hit3 reports",hit3,328,7,2,4,33,0,0);
coll(&image,"hit4 reports",hit4,328,7,1,4,25,0,0);
coll(&image,"hit5 reports",hit5,328,7,3,4,43,0,0);
coll(&image,"out reports","module m\ntarget x86_64-nexora-none\nsection .text {\nfn f(out a:u64 @rdx,in b:u64,in c:u64,in d:u64)->u64\neffects {}\nclobbers {} {\nreturn b\n}\n}\n",328,7,1,4,21,0,0);
coll(&image,"invalid source","target x86_64-nexora-none\n",800,0,0,0,0,0,0);
 }
 /* ---- W5-L4 direction reader conformance ---- */
 const char *p2[] = {"<generated abi_direction_probe>",
  "compiler/nova/analysis/abi/abi.nova",
  "compiler/nova/analysis/calls/calls.nova",
  "compiler/nova/analysis/calls/call_types.nova",
  "compiler/nova/analysis/types/initializer_types.nova",
  "compiler/nova/backend/x64/x64_lower_nxo.nova",
  "compiler/nova/backend/x64/x64_lower_control.nova",
  "compiler/nova/backend/x64/x64_lower_fixed.nova",
  "compiler/nova/backend/x64/x64_fixed.nova",
  "compiler/nova/formats/nxo/nxo.nova",
  "compiler/nova/formats/pe/pe.nova",
  "compiler/nova/analysis/abi/clobbers.nova",
  "compiler/nova/analysis/types/register_widths.nova",
  "compiler/nova/frontend/register_bindings.nova",
  "compiler/nova/frontend/parameters.nova",
  "compiler/nova/analysis/calls/callable_names.nova",
  "compiler/nova/analysis/semantics.nova",
  "compiler/nova/frontend/parser.nova",
  "compiler/nova/frontend/ast.nova",
  "compiler/nova/frontend/lexer.nova",
        "compiler/nova/macros/macro_splice.nova",
        "compiler/nova/macros/macro_expand.nova",
        "compiler/nova/macros/constant_eval.nova",
        "compiler/nova/analysis/c_conversion.nova"};
 char *s2[24] = {0};NtFInput in2[24];int all2 = 1;
 s2[0] = dup_text(probe_entry);
 if (!s2[0]) all2 = 0;
 in2[0] = (NtFInput){p2[0], s2[0], s2[0] ? strlen(s2[0]) : 0};
 for (unsigned i = 1; i < 24; i++) { size_t n = 0; s2[i] = load(p2[i], &n); in2[i] = (NtFInput){p2[i], s2[i], n}; if (!s2[i]) all2 = 0; }
 CHECK(all2, "probe sources load");
 NtArtifact a2 = {0};
 int compiled2 = all2 && nova_compile_many_v2(in2, 24, &a2);
 CHECK(compiled2, "probe modules compile");
 if (!compiled2) fprintf(stderr, "E%u %zu:%zu %s\n", a2.error.code, a2.error.line, a2.error.column, a2.error.message);
 NovaHostImage image2 = {0};
 CHECK(compiled2 && nova_host_map(&a2, &image2), "probe image maps");
 if (image2.memory) { for (unsigned i = 0; i < DIR_ROWS; i++) dir_case(&image2, &dir_rows[i]); }
 if (image2.memory) { for (unsigned i = 0; i < SEL_ROWS; i++) sel_case(&image2, &sel_rows[i]); }
 /* ---- W10-L4 profile conformance: a third artifact, and the smallest one
  * in the file, because the profile rules need the parser and nothing else.
  * abi.nova pulls register_widths and clobbers, and the parser pulls the
  * lexer and the ast, so seven inputs is the whole closure. ---- */
 const char *p3[] = {"<generated abi_profile_probe>",
  "compiler/nova/analysis/abi/abi.nova",
  "compiler/nova/analysis/abi/clobbers.nova",
  "compiler/nova/analysis/types/register_widths.nova",
  "compiler/nova/frontend/parser.nova",
  "compiler/nova/frontend/ast.nova",
  "compiler/nova/frontend/lexer.nova"};
 char *s3[7] = {0};NtFInput in3[7];int all3 = 1;
 s3[0] = dup_text(profile_entry);
 if (!s3[0]) all3 = 0;
 in3[0] = (NtFInput){p3[0], s3[0], s3[0] ? strlen(s3[0]) : 0};
 for (unsigned i = 1; i < 7; i++) { size_t n = 0; s3[i] = load(p3[i], &n); in3[i] = (NtFInput){p3[i], s3[i], n}; if (!s3[i]) all3 = 0; }
 CHECK(all3, "profile probe sources load");
 NtArtifact a3 = {0};
 int compiled3 = all3 && nova_compile_many_v2(in3, 7, &a3);
 CHECK(compiled3, "profile probe modules compile");
 if (!compiled3) fprintf(stderr, "E%u %zu:%zu %s\n", a3.error.code, a3.error.line, a3.error.column, a3.error.message);
 NovaHostImage image3 = {0};
 CHECK(compiled3 && nova_host_map(&a3, &image3), "profile probe image maps");
 if (image3.memory) { for (unsigned i = 0; i < PROF_ROWS; i++) prof_case(&image3, &prof_rows[i]); }
 /* The structural half of the drift detector: it reads the tree, not the
  * image, so it runs whether or not the probe mapped. */
 scan_direction_copies();
 /* The same tree read by the rule's SHAPE rather than by its name. The name
  * scan above cannot see a copy that was renamed, which is the whole of the
  * D5 residual; this one is anchored on what the copies COMPUTE. */
 scan_direction_rule_shape();
 /* The set derivation and the profile-scope pin read the tree, not the
  * image, so they run whether or not the probe mapped. */
 scan_saved_register_copies();
 pin_abi_profile_scope();
 /* ---- lot 24: a fourth artifact, the only one that carries BOTH sides of
  * the question. The three above each answer one query; this one answers the
  * query AND the pass that consumes it from the same parse of the same source,
  * which is the only way a stale credit is visible at all: it is a 0 in the
  * proved count, and a 0 is what a correct program produces too. The module
  * list is tests_ntasm_call_contracts.c's, which is already the proven closure
  * for call_contracts.nova plus everything it imports, with this entry in
  * place of that gate's own. ---- */
 const char *p4[] = {"tests/nova/tests/invalidation-entry.nova",
  "compiler/nova/analysis/calls/call_contracts.nova",
  "compiler/nova/analysis/abi/abi.nova",
  "compiler/nova/analysis/types/register_widths.nova",
  "compiler/nova/analysis/abi/clobbers.nova",
  "compiler/nova/frontend/parser.nova",
  "compiler/nova/frontend/ast.nova",
  "compiler/nova/frontend/lexer.nova",
  "compiler/nova/analysis/abi/effects.nova",
  "compiler/nova/analysis/abi/features.nova"};
 char *s4[10] = {0}; NtFInput in4[10]; int all4 = 1;
 for (unsigned i = 0; i < 10; i++) { size_t n = 0; s4[i] = load(p4[i], &n); in4[i] = (NtFInput){p4[i], s4[i], n}; if (!s4[i]) all4 = 0; }
 CHECK(all4, "invalidation sources load");
 NtArtifact a4 = {0};
 int compiled4 = all4 && nova_compile_many_v2(in4, 10, &a4);
 CHECK(compiled4, "invalidation modules compile");
 if (!compiled4) fprintf(stderr, "E%u %zu:%zu %s\n", a4.error.code, a4.error.line, a4.error.column, a4.error.message);
 NovaHostImage image4 = {0};
 CHECK(compiled4 && nova_host_map(&a4, &image4), "invalidation image maps");
 if (image4.memory) { for (unsigned i = 0; i < INV_ROWS; i++) inv_case(&image4, &inv_rows[i]); }
 /* The red proof runs on its own, whether or not the image above mapped, so a
  * compile failure cannot hide a proof that would have gone red. */
 if (all4) inv_red_proof(p4, 10, (const char **)s4);
 if (image4.memory) nova_host_unmap(&image4);
 if (image3.memory) nova_host_unmap(&image3);
 if (image2.memory) nova_host_unmap(&image2);
 if (image.memory) nova_host_unmap(&image);
 if (compiled) nt_artifact_free(&a);
 if (compiled2) nt_artifact_free(&a2);
 if (compiled3) nt_artifact_free(&a3);
 if (compiled4) nt_artifact_free(&a4);
 for (unsigned i = 0; i < 11; i++) free(sources[i]);
 for (unsigned i = 0; i < 24; i++) free(s2[i]);
 for (unsigned i = 0; i < 7; i++) free(s3[i]);
 for (unsigned i = 0; i < 10; i++) free(s4[i]);
 printf("NTASM_NOVA_ABI checks=%u failures=%u cases=%u\n", checks, failures, cases);
 return failures ? 1 : 0;
}
