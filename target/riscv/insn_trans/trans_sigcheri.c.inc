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
