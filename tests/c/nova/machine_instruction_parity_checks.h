/* Runs in machine_corpus with its independent PE loader and bounded child execution. */
static void machine_instruction_parity_checks(NtMachineImage *producer) {
    unsigned checks_before=checks, failures_before=failures, cases_before=cases;
    const char *ops[]={"add","sub","cmp","and","or","xor","test","mov","shl","shr","sar"};
    const char *destinations[]={"rax","eax","ax","al","ah"};
    const char *registers[]={"r10","r10d","r10w","r10b","bl"};
    const char *values[]={"0","127","128","2147483647","2147483648","4294967295","4294967296","-1","-2147483648","-2147483649","0xffffffffffffffff"};
    unsigned agree=0,refused=0,c_only=0,mir_only=0,wrong=0,faults=0,range_refusals=0;
    for(unsigned op=0;op<sizeof ops/sizeof *ops;op++) {
        for(unsigned width=0;width<sizeof destinations/sizeof *destinations;width++) {
        for(unsigned v=0;v<sizeof values/sizeof *values;v++) {
            /* The register controls retain a large literal, without making it an immediate operand. */
            for(unsigned via_register=0;via_register<2;via_register++) {
                char source[1024],setup[128];
                int shift=!strcmp(ops[op],"shl")||!strcmp(ops[op],"shr")||!strcmp(ops[op],"sar");
                snprintf(setup,sizeof setup,"mov %s,%s\n",shift?"rcx":width==4?"rbx":"r10",values[v]);
                int len=snprintf(source,sizeof source,
                    "module parity\ntarget x86_64-nexora-uefi\nsection .text {\n"
                    "export fn main()->u64\neffects {changes_flags}\nclobbers {rax,rbx,rcx,r10,rflags} {\n"
                    "mov rax,0x1122334455667788\n%s%s %s,%s\nreturn rax\n}\n}\n",
                    via_register?setup:"",ops[op],destinations[width],via_register?(shift?"cl":registers[width]):values[v]);
                CHECK(len>0&&(size_t)len<sizeof source,"fixture fits");
                if(len<0||(size_t)len>=sizeof source)continue;
                NtFInput in={"immediate-parity.ntasm",source,(size_t)len};NtArtifact c={0};
                int c_ok=nt_compile_many(&in,1,&c);
                if(c_ok)c_ok=nt_make_pe(&c);
                NtBuffer pe={0};NtMachineReport report={0};
                int m_ok=nt_machine_pe(producer,source,(size_t)len,&pe,&report);
                cases++;
                if(!c_ok&&!via_register&&c.error.code==401)range_refusals++;
                const char *verdict="REFUSED_BOTH";
                if(report.runtime){faults++;verdict="FAULT";CHECK(0,"%s %s runtime=%" PRIu64,ops[op],values[v],report.runtime);}
                else if(c_ok&&m_ok) {
                    uint64_t a=0,b=0;char wa[200]={0},wb[200]={0};
                    int ca=run_child(c.pe.bytes,c.pe.size,&a,wa,sizeof wa);
                    int ma=run_child(pe.bytes,pe.size,&b,wb,sizeof wb);
                    if(ca||ma){faults++;verdict="FAULT";CHECK(0,"execution %s %s C=%d %s MIR=%d %s",ops[op],values[v],ca,wa,ma,wb);}
                    else if(a!=b){wrong++;verdict="WRONG";CHECK(0,"%s %s C=%" PRIu64 " MIR=%" PRIu64,ops[op],values[v],a,b);}
                    else {agree++;verdict="AGREE";}
                } else if(c_ok&&!m_ok) {c_only++;verdict="C_ONLY";CHECK(0,"MIR rejects valid %s %s register=%u stage=%" PRIu64 " code=%" PRIu64,ops[op],values[v],via_register,report.stage,report.code);}
                else if(!c_ok&&m_ok) {mir_only++;verdict="MIR_ONLY";CHECK(0,"MIR accepts C-refused %s %s register=%u E%u",ops[op],values[v],via_register,c.error.code);}
                else refused++;
                printf("IMMEDIATE op=%s dst=%s value=%s register=%u verdict=%s c_code=%u mir_code=%" PRIu64 " runtime=%" PRIu64 "\n",ops[op],destinations[width],values[v],via_register,verdict,c.error.code,report.code,report.runtime);
                free(pe.bytes);nt_artifact_free(&c);
            }
        }
    }
    }
    const char *invalid[]={"mov ah,r8b","mov r8b,ah","add ah,r8b","cmp ah,r8b",
        "shl rax,dl","shr rax,dl","sar rax,dl","shl rax,256","shr rax,256","sar rax,256",
        "mov al,256","mov ax,65536","mov eax,4294967296","lea rax,rbx","idiv rax,rbx","div rax,rbx"};
    for(unsigned i=0;i<sizeof invalid/sizeof *invalid;i++) {
        char source[1024];int n=snprintf(source,sizeof source,
          "module invalid_form\ntarget x86_64-nexora-uefi\nsection .text {\n"
          "export fn main()->u64\neffects {changes_flags}\nclobbers {rax,rbx,rcx,rdx,r8,rflags} {\n"
          "mov rax,7\nmov rbx,3\nmov rcx,2\nmov rdx,1\nmov r8,5\n%s\nreturn rax\n}\n}\n",invalid[i]);
        NtFInput in={"invalid-form.ntasm",source,(size_t)n};NtArtifact c={0};
        int c_ok=nt_compile_many(&in,1,&c);if(c_ok)c_ok=nt_make_pe(&c);
        NtBuffer pe={0};NtMachineReport report={0};int m_ok=nt_machine_pe(producer,source,(size_t)n,&pe,&report);cases++;
        CHECK(!c_ok&&(c.error.code==400||c.error.code==401||c.error.code==402),"reference rejects encoded form %s as E400/E401/E402 (got E%u)",invalid[i],c.error.code);
        if(report.runtime){faults++;CHECK(0,"invalid %s causes runtime fault",invalid[i]);}
        else if(m_ok){mir_only++;CHECK(0,"MIR accepts invalid encoding %s",invalid[i]);}
        else if(c_ok){c_only++;CHECK(0,"fixture unexpectedly accepted by C: %s",invalid[i]);}
        else {refused++;CHECK(pe.size==0,"invalid %s delivers no partial image",invalid[i]);}
        printf("ENCODING_REFUSAL source=%s c_ok=%d c_code=%u mir_ok=%d mir_code=%" PRIu64 " runtime=%" PRIu64 "\n",invalid[i],c_ok,c.error.code,m_ok,report.code,report.runtime);
        free(pe.bytes);nt_artifact_free(&c);
    }
    /* Targeted regression witnesses from the core review. Positive rows
     * pin a full u64 value as well as both producers; negatives pin C's code. */
    const struct {const char *name,*body;unsigned c_code;uint64_t expected;} extra[]={
      {"mem-immediate-full-width","mov [b]:ptr<user,u64>,3\nload rax,[b]:ptr<user,u64>\n",0,3},
      {"mem-immediate-negative","mov [b]:ptr<user,u64>,-1\nload rax,[b]:ptr<user,u64>\n",0,UINT64_MAX},
      {"mem-immediate-range","mov [b]:ptr<user,u64>,2147483647+1\n",401,0},
      {"mem-register-width-mismatch","mov [b]:ptr<user,u64>,al\n",400,0},
      {"constant-precedence","mov rax,1+2*3\n",0,7},
      {"constant-negative-subtraction","add rax,0-1\n",0,6},
      {"constant-positive-boundary","add rax,2147483646+1\n",0,UINT64_C(2147483654)},
      {"constant-positive-out-of-range","add rax,2147483647+1\n",401,0},
      {"constant-negative-out-of-range","add rax,0-2147483649\n",401,0},
      {"constant-unsigned-all-ones","mov rax,~0\n",0,UINT64_MAX},
      {"constant-unsigned-imm32","add rax,~0\n",401,0},
      {"constant-overflow","mov rax,18446744073709551615+1\n",400,0},
      {"mul64-one-operand","mul rbx\n",0,21},
      {"mul64-high-half","mov rax,0xffffffffffffffff\nmov rbx,2\nmul rbx\nmov rax,rdx\n",0,1},
      {"mul8-ax-slice","mov rax,0x11223344556600ff\nmov rbx,2\nmul bl\n",0,UINT64_C(0x11223344556601fe)},
      {"mul16-dx-slice","mov rax,65535\nmov rbx,2\nmul bx\nmov rax,rdx\n",0,UINT64_C(0x1122334455660001)},
      {"mul32-dx-zero-extension","mov eax,4294967295\nmov rbx,2\nmul ebx\nmov rax,rdx\n",0,1},
      {"mul-two-operands-invalid","mul rax,rbx\n",400,0},
      {"imul-two-operands","mov rax,-7\nimul rax,rbx\n",0,UINT64_MAX-20},
      {"imul-three-operands","mov rax,99\nimul rax,rbx,3\n",0,9},
      {"imul-three-signed-immediate","imul rax,rbx,-1\n",0,UINT64_MAX-2},
      {"imul-one-operand-invalid","imul rbx\n",400,0},
      {"imul-two-immediate-invalid","imul rax,3\n",400,0},
      {"imul-three-immediate-range","imul rax,rbx,2147483648\n",401,0},
      {"div64-one-operand","mov rax,42\nmov rdx,0\nmov rcx,2\ndiv rcx\n",503,0},
      {"idiv64-one-operand","mov rax,42\nmov rdx,0\nmov rcx,2\nidiv rcx\n",503,0},
      {"div64-remainder","mov rax,43\nmov rdx,0\nmov rcx,2\ndiv rcx\nmov rax,rdx\n",503,0},
      {"idiv64-negative-quotient","mov rax,-43\nmov rdx,-1\nmov rcx,2\nidiv rcx\n",503,0},
      {"idiv64-negative-remainder","mov rax,-43\nmov rdx,-1\nmov rcx,2\nidiv rcx\nmov rax,rdx\n",503,0},
      {"div8-ax-packed-remainder","mov rax,0x112233445566002b\nmov rbx,2\ndiv bl\n",503,0},
      {"div16-dx-preservation","mov rax,42\nmov rdx,0x1122334455660000\nmov rbx,2\ndiv bx\nmov rax,rdx\n",503,0},
      {"div32-dx-zero-extension","mov rax,42\nmov rdx,0x1122334400000000\nmov rbx,2\ndiv ebx\nmov rax,rdx\n",503,0},
      {"div-flags-undefined","mov rax,42\nmov rdx,0\nmov rcx,2\ndiv rcx\nje zero\nzero:\n",503,0}

    };
    for(unsigned i=0;i<sizeof extra/sizeof *extra;i++) {
      char source[2048];int n=snprintf(source,sizeof source,
        "module core_regression\ntarget x86_64-nexora-uefi\nsection .data {\n"
        "data b:u64=0x1122334455667788\n}\nsection .text {\n"
        "export fn main()->u64\neffects {reads_mem(user),writes_mem(user),changes_flags}\n"
        "clobbers {rax,rbx,rcx,rdx,rflags} {\nmov rax,7\nmov rbx,3\n"
        "mov rcx,0x1122334455667700\nmov rdx,0x1122334455667700\n%sreturn rax\n}\n}\n",extra[i].body);
      CHECK(n>0&&(size_t)n<sizeof source,"core fixture fits: %s",extra[i].name);
      if(n<0||(size_t)n>=sizeof source)continue;
      NtFInput in={extra[i].name,source,(size_t)n};NtArtifact c={0};
      int c_ok=nt_compile_many(&in,1,&c);if(c_ok)c_ok=nt_make_pe(&c);
      NtBuffer pe={0};NtMachineReport r={0};int m_ok=nt_machine_pe(producer,source,(size_t)n,&pe,&r);cases++;
      if(extra[i].c_code) {
        CHECK(!c_ok&&c.error.code==extra[i].c_code,"%s C refusal pinned E%u got E%u %s",extra[i].name,extra[i].c_code,c.error.code,c.error.message);
        CHECK(!m_ok&&r.runtime==0&&r.code!=0&&pe.size==0,"%s MIR refuses with diagnostic and no bytes",extra[i].name);
        if(!strncmp(extra[i].name,"div",3)||!strncmp(extra[i].name,"idiv",4)) {
          if(!strcmp(extra[i].name,"div-flags-undefined")) CHECK(r.stage==3&&r.code==940,"DIV undefined flags pinned stage3/code940");
          else CHECK(r.stage==7&&r.code==981,"DIV runtime safety refusal pinned stage7/code981");
        }
        if(!c_ok&&!m_ok&&!r.runtime)refused++;
        else if(r.runtime)faults++;else if(m_ok&&!c_ok)mir_only++;else c_only++;
      } else {
        CHECK(c_ok,"%s reference accepts: E%u %s",extra[i].name,c.error.code,c.error.message);
        CHECK(m_ok&&r.runtime==0,"%s MIR accepts: stage=%" PRIu64 " code=%" PRIu64,extra[i].name,r.stage,r.code);
        if(c_ok&&m_ok&&!r.runtime) {
          uint64_t cv=0,mv=0;char cw[200]={0},mw[200]={0};
          int cr=run_child(c.pe.bytes,c.pe.size,&cv,cw,sizeof cw),mr=run_child(pe.bytes,pe.size,&mv,mw,sizeof mw);
          CHECK(cr==0&&mr==0,"%s both execute: C=%d %s MIR=%d %s",extra[i].name,cr,cw,mr,mw);
          CHECK(cv==extra[i].expected&&mv==cv,"%s full value expected=%" PRIu64 " C=%" PRIu64 " MIR=%" PRIu64,extra[i].name,extra[i].expected,cv,mv);
          if(cr||mr)faults++;else if(cv!=mv||cv!=extra[i].expected)wrong++;else agree++;
        } else if(r.runtime)faults++;else if(c_ok&&!m_ok)c_only++;else if(m_ok&&!c_ok)mir_only++;else refused++;
      }
      printf("CORE_REGRESSION %s c_ok=%d c_code=%u mir_ok=%d mir_stage=%" PRIu64 " mir_code=%" PRIu64 " runtime=%" PRIu64 "\n",extra[i].name,c_ok,c.error.code,m_ok,r.stage,r.code,r.runtime);
      free(pe.bytes);nt_artifact_free(&c);
    }
    CHECK(range_refusals>0,"at least one reference E401 is exercised");
    CHECK(agree>0,"valid forms actually execute");
    CHECK(agree+refused+c_only+mir_only+wrong+faults==cases-cases_before,"every case has an outcome");
    printf("NTASM_NOVA_MACHINE_INSTRUCTION_PARITY checks=%u failures=%u cases=%u agree=%u refused=%u c_only=%u mir_only=%u wrong=%u faults=%u range_refusals=%u\n",checks-checks_before,failures-failures_before,cases-cases_before,agree,refused,c_only,mir_only,wrong,faults,range_refusals);
}
