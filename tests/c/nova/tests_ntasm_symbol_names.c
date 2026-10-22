#include "../../../compiler/c/nova/frontend/nova.h"
#include "../../../compiler/c/nova/runtime/run_host.h"
#include "../../../compiler/c/nova/runtime/runtime_v2.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks,failures,cases;
#define CHECK(c,m) do{checks++;if(!(c)){failures++;fprintf(stderr,"FAIL %s\n",m);}}while(0)
static const uint64_t guard=UINT64_C(0xcccccccccccccccc);
static char*load(const char*p,size_t*n){FILE*f=fopen(p,"rb");if(!f)return NULL;fseek(f,0,SEEK_END);long z=ftell(f);fseek(f,0,SEEK_SET);char*b=z>=0?malloc((size_t)z+1):NULL;if(!b||fread(b,1,(size_t)z,f)!=(size_t)z){free(b);fclose(f);return NULL;}fclose(f);b[z]=0;*n=(size_t)z;return b;}
typedef struct{uint64_t returned,runtime,out[4];}Run;
static Run run(const NovaHostImage*i,const char*s,uint64_t words){Run r={.out={guard,guard,guard,guard}};NovaContextV2 c={0};CHECK(nova_context_init_v2(&c),"context init");uint64_t sh=nova_borrow_v2(&c,(void*)s,strlen(s),0),oh=nova_borrow_v2(&c,r.out,words*8,1);uint64_t a[]={sh,strlen(s),oh,words};r.returned=i->entry(&c,a,4);r.runtime=c.error;CHECK(nova_context_destroy_v2(&c),"context cleanup");return r;}
/* out[0] functions, out[1] LINK names (data plus constant), out[2] imports,
 * out[3] declared names, which is the sum of the three. out[3] is checked
 * against that sum deliberately: a derived count that silently stops
 * including a category is how the constant gap survived in the first place,
 * because out[1] counted data only while the link table held data and
 * constant alike. Every ok call therefore states the total it implies. */
static void ok(const NovaHostImage*i,const char*n,const char*s,uint64_t f,uint64_t link,uint64_t imp){Run r=run(i,s,4);cases++;checks++;if(r.returned||r.runtime||r.out[0]!=f||r.out[1]!=link||r.out[2]!=imp||r.out[3]!=f+link+imp){failures++;fprintf(stderr,"FAIL ok %s ret=%llu out=%llu,%llu,%llu,%llu want=%llu,%llu,%llu total=%llu\n",n,(unsigned long long)r.returned,(unsigned long long)r.out[0],(unsigned long long)r.out[1],(unsigned long long)r.out[2],(unsigned long long)r.out[3],(unsigned long long)f,(unsigned long long)link,(unsigned long long)imp,(unsigned long long)(f+link+imp));}}
static void err(const NovaHostImage*i,const char*n,const char*s,uint64_t words,uint64_t code,int untouched){Run r=run(i,s,words);cases++;checks++;if(r.returned!=code||r.runtime||(untouched&&(r.out[0]!=guard||r.out[1]!=guard))||(!untouched&&r.out[0]==guard)){failures++;fprintf(stderr,"FAIL error %s ret=%llu\n",n,(unsigned long long)r.returned);}}
int main(void){const char*paths[]={"tests/nova/tests/symbol-names-entry.nova","compiler/nova/frontend/symbol_names.nova","compiler/nova/analysis/calls/callable_names.nova","compiler/nova/analysis/semantics.nova","compiler/nova/frontend/parser.nova","compiler/nova/frontend/ast.nova","compiler/nova/frontend/lexer.nova"};char*sources[7]={0};NtFInput inputs[7];for(unsigned i=0;i<7;i++){size_t n=0;sources[i]=load(paths[i],&n);inputs[i]=(NtFInput){paths[i],sources[i],n};}int all=1;for(unsigned i=0;i<7;i++)if(!sources[i])all=0;CHECK(all,"sources load");NtArtifact a={0};int compiled=all&&nova_compile_many_v2(inputs,7,&a);CHECK(compiled,"modules compile");if(!compiled)fprintf(stderr,"E%u %zu:%zu %s\n",a.error.code,a.error.line,a.error.column,a.error.message);NovaHostImage image={0};CHECK(compiled&&nova_host_map(&a,&image),"image maps");
 if(image.memory){const char*unique="module m\ntarget x86_64-nexora-none\nimport a.f as ext: fn()->u64\neffects {}\nclobbers {}\nsection .rdata {\ndata value:u64=1\n}\nsection .text {\nfn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";ok(&image,"unique",unique,1,1,1);
 /* The C oracle keeps TWO disjoint name namespaces and this pass kept one.
  * duplicate_function (frontend.c:2950) is called by parse_function
  * (:3043) and by parse_import (:2968) and walks functions only, so a
  * function name and an import alias are the SAME name. The variable loop
  * in parse_data (:3163) and parse_constant (:3240) walks module globals
  * only, so a data name and a constant name are the SAME name. Neither loop
  * ever looks at the other table, and neither reads fn->section or
  * v->section, so both are MODULE wide.
  *
  * Every verdict below was read off compiler/c nt_object_compile
  * on this exact source, never off the Nova producer. The cross namespace
  * shapes are ACCEPTED, in both declaration orders and across sections:
  *   fn/data, data/fn, import/data, data/import, fn/const, const/fn,
  *   import/const, const/import  -> all ACCEPT, two symbols
  * and the same namespace shapes are all REFUSED:
  *   fn/fn, import/import, fn/import  -> REFUSE duplicate function
  *   data/data, const/const, data/const -> REFUSE duplicate data or constant
  * A single namespace refused the eight accepted shapes, so a function and a
  * data item of one name was a valid program the oracle compiles. */
 const char*cross="module m\ntarget x86_64-nexora-none\nsection .rdata {\ndata same:u64=1\n}\nsection .text {\nfn same()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";ok(&image,"data and function same name",cross,1,1,0);
 const char*cross_rev="module m\ntarget x86_64-nexora-none\nsection .text {\nfn same()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\nsection .rdata {\ndata same:u64=1\n}\n";ok(&image,"function and data same name reversed",cross_rev,1,1,0);
 const char*imp_data="module m\ntarget x86_64-nexora-none\nimport a.same as same: fn()->u64\neffects {}\nclobbers {}\nsection .rdata {\ndata same:u64=1\n}\n";ok(&image,"import alias and data same name",imp_data,0,1,1);
 const char*data_imp="module m\ntarget x86_64-nexora-none\nsection .rdata {\ndata same:u64=1\n}\nimport a.same as same: fn()->u64\neffects {}\nclobbers {}\n";ok(&image,"data and import alias same name",data_imp,0,1,1);
 /* Section pairing carries no weight: the two namespaces are independent of
  * it, so the same two names in two different data sections are still two
  * names, and a function is accepted in a data section at all. */
 const char*two_data_sections="module m\ntarget x86_64-nexora-none\nsection .rdata {\nfn same()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\nsection .data {\ndata same:u64=1\n}\n";ok(&image,"function in rdata, data in data section",two_data_sections,1,1,0);
 const char*fn_data_same_section="module m\ntarget x86_64-nexora-none\nsection .rdata {\ndata same:u64=1\nfn same()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";ok(&image,"data and function one section",fn_data_same_section,1,1,0);
 /* The negative direction, which is the one that fails dangerously.
  * Within ONE namespace a duplicate is still a duplicate. Note which pass
  * owns which: a same section data pair is refused by semantics.index as 300
  * and an import alias pair by callable_names.check as 313, both ahead of
  * this one, so after the split 319 is reachable here for data alone. */
 const char*dup_data="module m\ntarget x86_64-nexora-none\nsection .rdata {\ndata same:u64=1\ndata same:u64=2\n}\n";err(&image,"two data one section",dup_data,4,300,0);
 const char*sections="module m\ntarget x86_64-nexora-none\nsection .rdata {\ndata same:u64=1\n}\nsection .data {\ndata same:u64=2\n}\n";err(&image,"data sections",sections,4,319,0);
 const char*aliases="module m\ntarget x86_64-nexora-none\nimport a.f as x: fn()->u64\neffects {}\nclobbers {}\nimport b.f as x: fn()->u64\neffects {}\nclobbers {}\n";err(&image,"upstream aliases",aliases,4,313,0);
 const char*fn_import="module m\ntarget x86_64-nexora-none\nimport a.f as same: fn()->u64\neffects {}\nclobbers {}\nsection .text {\nfn same()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";err(&image,"import alias and function same name",fn_import,4,313,0);
 const char*dup_fn_sections="module m\ntarget x86_64-nexora-none\nsection .text {\nfn same()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\nsection .rdata {\nfn same()->u64\neffects {}\nclobbers {} {\nreturn 1\n}\n}\n";err(&image,"two functions in two sections",dup_fn_sections,4,313,0);
 /* spec/ntasm/ntasm.md 13 develops a macro before the final verification, so a
  * declaration written only inside a macro(13) subtree is not a declaration
  * of the module and its name never entered either namespace. The oracle
  * accepts the first, one symbol, and refuses the second on the two REAL
  * data items. */
 const char*tpl_fn="module m\ntarget x86_64-nexora-none\nmacro mk()->ast.decl {\nreturn quote(decl) {\nfn same()->u64\neffects {}\nclobbers {} {\nreturn 1;\n}\n};\n}\nsection .text {\nfn same()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";ok(&image,"template function then real function",tpl_fn,1,0,0);
 const char*tpl_data="module m\ntarget x86_64-nexora-none\nmacro mk()->ast.decl {\nreturn quote(decl) {\ndata same:u64=9\n};\n}\nsection .rdata {\ndata same:u64=1\n}\nsection .data {\ndata same:u64=2\n}\n";err(&image,"template plus two real data",tpl_data,4,319,0);
 const char*data="module m\ntarget x86_64-nexora-none\nsection .rdata {\ndata a:u64=1\ndata b:u64=2\n}\n";ok(&image,"data",data,0,2,0);
 /* The constant half of the link namespace, kind 10. This is the half that
  * was MISSING rather than over-strict: the pass accepted all three shapes
  * below while the oracle refused them, so two module globals shared a name
  * in silence. Read off nt_object_compile on these exact sources:
  *   const same / const same      REFUSE duplicate constant 'same'
  *   const same / data same       REFUSE duplicate data 'same'
  *   data same / const same       REFUSE duplicate constant 'same'
  * so the refusal is the same rule in both orders and the message names the
  * offending kind. This is a narrowing, and the only one in this pass's
  * history: every refusal it adds is one the oracle also raises. */
 const char*two_const="module m\ntarget x86_64-nexora-none\nconst same:u64=1\nconst same:u64=2\n";err(&image,"two constants",two_const,4,319,0);
 const char*const_data="module m\ntarget x86_64-nexora-none\nconst same:u64=1\nsection .rdata {\ndata same:u64=2\n}\n";err(&image,"constant then data",const_data,4,319,0);
 const char*data_const="module m\ntarget x86_64-nexora-none\nsection .rdata {\ndata same:u64=1\n}\nconst same:u64=2\n";err(&image,"data then constant",data_const,4,319,0);
 /* A constant is a LINK name, so it still crosses the other table freely.
  * Oracle: all four ACCEPT, one symbol, because a constant is not a symbol. */
 const char*const_fn="module m\ntarget x86_64-nexora-none\nconst same:u64=1\nsection .text {\nfn same()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";ok(&image,"constant and function same name",const_fn,1,1,0);
 const char*fn_const="module m\ntarget x86_64-nexora-none\nsection .text {\nfn same()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\nconst same:u64=1\n";ok(&image,"function and constant same name",fn_const,1,1,0);
 const char*imp_const="module m\ntarget x86_64-nexora-none\nimport a.same as same: fn()->u64\neffects {}\nclobbers {}\nconst same:u64=1\n";ok(&image,"import alias and constant same name",imp_const,0,1,1);
 const char*const_imp="module m\ntarget x86_64-nexora-none\nconst same:u64=1\nimport a.same as same: fn()->u64\neffects {}\nclobbers {}\n";ok(&image,"constant and import alias same name",const_imp,0,1,1);
 /* The mask keys on the kind of the ROOT, not of what sits under it, so a
  * declaration of ANY kind inside a macro is excluded and a real link name
  * outside is free to take the same name. These two are the proof, because
  * each pairs a template declaration of one kind with a real declaration of
  * the other table's kind: a mask that only handled functions, or a scan
 * that only compared same-kind pairs, would refuse them. Oracle: both
 * ACCEPT, one symbol, and that one symbol is the real `fn main`, so out[0]
 * is 1 for it and out[1] is 1 for the constant the template did not shield. */
 const char*tpl_data_const="module m\ntarget x86_64-nexora-none\nmacro mk()->ast.decl {\nreturn quote(decl) {\ndata same:u64=9\n};\n}\nconst same:u64=1\nsection .text {\nfn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";ok(&image,"template data then real constant",tpl_data_const,1,1,0);
 const char*tpl_fn_const="module m\ntarget x86_64-nexora-none\nmacro mk()->ast.decl {\nreturn quote(decl) {\nfn same()->u64\neffects {}\nclobbers {} {\nreturn 1;\n}\n};\n}\nconst same:u64=1\nsection .text {\nfn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";ok(&image,"template function then real constant",tpl_fn_const,1,1,0);
 /* The counter. Two constants and a data item are three link names, and one
  * function is one callable name, so out[3] is 4 and not 3. Oracle: ACCEPT,
  * two symbols, the data item and the function; a constant is a name but not
  * a symbol, and the count has to say so. */
 const char*link_total="module m\ntarget x86_64-nexora-none\nconst a:u64=1\nconst b:u64=2\nsection .rdata {\ndata c:u64=3\n}\nsection .text {\nfn main()->u64\neffects {}\nclobbers {} {\nreturn 0\n}\n}\n";ok(&image,"two constants and a data",link_total,1,3,0);
 err(&image,"short",unique,3,800,1);err(&image,"invalid","target x86_64-nexora-none\n",4,800,1);}
 if(image.memory) nova_host_unmap(&image);
 if(compiled) nt_artifact_free(&a);
 for(unsigned i=0;i<7;i++) free(sources[i]);
 printf("NTASM_NOVA_SYMBOL_NAMES checks=%u failures=%u cases=%u\n",checks,failures,cases);
 return failures?1:0;
}
