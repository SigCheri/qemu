#define TRANS_KEY(NAME, FUNC_TYPE, KEY_SEL ...) \
    static bool trans_##NAME(DisasContext *ctx, arg_ ## NAME *a) \
    {                                   \
        TCGv src1 = tcg_temp_new();     \
        TCGv src2 = tcg_temp_new();     \
        TCGv dest = tcg_temp_new();     \
                                        \
        gen_get_gpr(src1, a->rs1);      \
        gen_get_gpr(src2, a->rs2);      \
                                        \
        uint64_t start = a->start;      \
        uint64_t end = a->end;          \
        if(start > end){                \
            start += end;               \
            end = start - end;          \
            start -= end;               \
        }                               \
        uint64_t mask = ((uint64_t)(-1) << (start * 8)) & ((uint64_t)(-1) >> ((7 - end) * 8));    \
        uint64_t keysel = KEY_SEL;                  \
                                                    \
        TCGv_i64 tcg_keysel = tcg_constant_i64(keysel); \
        TCGv_i64 tcg_mask = tcg_constant_i64(mask); \
                                                    \
        gen_helper_ ## FUNC_TYPE ## _op(dest, cpu_env, src1, src2, tcg_keysel, tcg_mask);     \
                                        \
        gen_set_gpr(a->rd, dest);       \
                                        \
        tcg_temp_free(src1);            \
        tcg_temp_free(src2);            \
        tcg_temp_free(dest);            \
                                        \
        return true;                    \
    }

TRANS_KEY(cremk, encrypt, 0)
TRANS_KEY(cresk, encrypt, 1)
TRANS_KEY(crdmk, decrypt, 0)
TRANS_KEY(crdsk, decrypt, 1)

static bool trans_lc_tweak(DisasContext *ctx, arg_lc_tweak *a){
    TCGv gpr_addr = tcg_temp_new();
    TCGv gpr_result = tcg_temp_new();
    gen_get_gpr(gpr_addr, a->rs1);
    tcg_gen_addi_tl(gpr_addr, gpr_addr, a->imm);
    TCGv_i64 offsel = tcg_constant_i64(a->sel);
    TCGv_i32 authreg = tcg_constant_i32(a->rs1);

    if(ctx->capmode){
        gen_helper_load_tweak_via_cap(gpr_result, cpu_env, gpr_addr, authreg, offsel);
    }else{
        gen_helper_load_tweak_via_ddc(gpr_result, cpu_env, gpr_addr, offsel);
    }

    gen_set_gpr(a->rd, gpr_result);
    tcg_temp_free(gpr_addr);
    tcg_temp_free(gpr_result);
    return true;
}

static bool trans_sc_tweak(DisasContext *ctx, arg_sc_tweak *a){
    TCGv gpr_addr = tcg_temp_new();
    TCGv gpr_value = tcg_temp_new();
    gen_get_gpr(gpr_addr, a->rs1);
    tcg_gen_addi_tl(gpr_addr, gpr_addr, a->imm);
    gen_get_gpr(gpr_value, a->rs2);
    TCGv_i32 authreg = tcg_constant_i32(a->rs1);

    if(ctx->capmode){
        gen_helper_store_tweak_via_cap(cpu_env, gpr_addr, authreg, gpr_value);
    }else{
        gen_helper_store_tweak_via_ddc(cpu_env, gpr_addr, gpr_value);
    }

    tcg_temp_free(gpr_addr);
    tcg_temp_free(gpr_value);
    return true;
}

#define TRANS_LC_SIG(INDEX) \
static bool trans_lc_sig_t##INDEX(DisasContext *ctx, arg_lc_sig_t##INDEX *a){   \
    TCGv gpr_addr = tcg_temp_new();                         \
    gen_get_gpr(gpr_addr, a->rs1);                          \
    tcg_gen_addi_tl(gpr_addr, gpr_addr, a->imm);            \
    TCGv_i64 offsel = tcg_constant_i64(INDEX);        \
    TCGv_i32 authreg = tcg_constant_i32(a->rs1);            \
    TCGv_i32 destreg = tcg_constant_i32(a->rd);             \
                                                            \
    if(ctx->capmode){                                       \
        gen_helper_load_sig_via_cap(cpu_env, destreg, gpr_addr, authreg, offsel); \
    }else{                                                  \
        gen_helper_load_sig_via_ddc(cpu_env, destreg, gpr_addr, offsel);          \
    }                                                       \
                                                            \
                                                            \
    tcg_temp_free(gpr_addr);                                \
    return true;                                            \
}

#define TRANS_SC_SIG(INDEX) \
static bool trans_sc_sig_t ## INDEX(DisasContext *ctx, arg_sc_sig_t ## INDEX *a){   \
    TCGv gpr_addr = tcg_temp_new();                         \
    gen_get_gpr(gpr_addr, a->rs1);                          \
    tcg_gen_addi_tl(gpr_addr, gpr_addr, a->imm);            \
    TCGv_i64 offsel = tcg_constant_i64(INDEX);        \
    TCGv_i32 authreg = tcg_constant_i32(a->rs1);            \
    TCGv_i32 srcreg = tcg_constant_i32(a->rs2);             \
                                                            \
    if(ctx->capmode){                                       \
        gen_helper_store_sig_via_cap(cpu_env, srcreg, gpr_addr, authreg, offsel); \
    }else{                                                  \
        gen_helper_store_sig_via_ddc(cpu_env, srcreg, gpr_addr, offsel);          \
    }                                                       \
                                                            \
                                                            \
    tcg_temp_free(gpr_addr);                                \
    return true;                                            \
}

TRANS_LC_SIG(0)
TRANS_LC_SIG(1)
TRANS_LC_SIG(2)
TRANS_LC_SIG(3)
TRANS_LC_SIG(4)
TRANS_LC_SIG(5)
TRANS_LC_SIG(6)

TRANS_SC_SIG(0)
TRANS_SC_SIG(1)
TRANS_SC_SIG(2)
TRANS_SC_SIG(3)
TRANS_SC_SIG(4)
TRANS_SC_SIG(5)
TRANS_SC_SIG(6)


