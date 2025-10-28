#include "qemu/osdep.h"
#include "qemu/log.h"
#include "cpu.h"
#include "qemu/main-loop.h"
#include "exec/exec-all.h"
#include "exec/log.h"
#include "exec/helper-proto.h"
#include "cheri-helper-utils.h"
#include "cheri_tagmem.h"
#include "qarma.h"
#ifndef TARGET_SIGCHERI
#error TARGET_SIGCHERI must be set
#endif

static void get_key_examine_priv(CPUArchState *env, uint64_t key_sel, target_ulong* keyl, target_ulong* keyh){
    target_ulong priv = env->priv;
    switch(key_sel){
        case 0:
            if(priv == 0)riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
            *keyl = env->mkey[0];
            *keyh = env->mkey[1];
            break;
        case 1:
            *keyl = env->skey[0];
            *keyh = env->skey[1];
            break;
        default:
            assert(false);
    }
}

target_ulong HELPER(encrypt_op)(CPUArchState *env, target_ulong plaintext, target_ulong tweak, uint64_t keysel, uint64_t mask){
    // printf("\nencrypt_op: GETPC = %016lx\n", GETPC());
    plaintext &= (target_ulong)mask;
    target_ulong keyl, keyh;
    // printf("encrypt_op: plaint = %016lx, tweak = %016lx, mask = %016lx\n", plaintext, tweak, mask);
    get_key_examine_priv(env, keysel, &keyl, &keyh);
    // printf("encrypt_op: key = %c, keyl = %016lx, keyh = %016lx\n", keysel?'s':'m', keyl, keyh);
    target_ulong result = qarma64_enc(plaintext, tweak, keyl, keyh, 7);
    // printf("encrypt_op: result = %016lx\n", result);
    return result;
}

target_ulong HELPER(decrypt_op)(CPUArchState *env, target_ulong secret, target_ulong tweak, uint64_t keysel, uint64_t mask){
    // printf("\ndecrypt_op: GETPC = %016lx\n", GETPC());
    
    target_ulong keyl, keyh;
    // printf("decrypt_op: secret = %016lx, tweak = %016lx, mask = %016lx\n", secret, tweak, mask);
    get_key_examine_priv(env, keysel, &keyl, &keyh);
    // printf("decrypt_op: key = %c, keyl = %016lx, keyh = %016lx\n", keysel?'s':'m', keyl, keyh);
    target_ulong result = qarma64_dec(secret, tweak, keyl, keyh, 7);
    // printf("decrypt_op: result = %016lx\n", result);
    if((result & (target_ulong)mask) == result){
        return result;
    }else{
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    }
}

static target_ulong inline get_off(CPUArchState *env, uint64_t offsel){
    assert(offsel >= 0 && offsel <= 7);
    return offsel == 0 ? 0 : env->tweakoff[offsel - 1];
}

static void inline set_off(CPUArchState *env, uint64_t offsel, target_ulong value){
    assert(offsel >= 0 && offsel <= 7);
    if(offsel != 0){
        env->tweakoff[offsel - 1] = value;
    }
}

static void load_sig_from_memory_raw(
    CPUArchState *env, target_ulong *pesbt, target_ulong *cursor, uint32_t cb,
    const cap_register_t *source, target_ulong vaddr, uintptr_t retpc)
{
    cheri_debug_assert(QEMU_IS_ALIGNED(vaddr, CHERI_CAP_SIZE));
    int mmu_idx = cpu_mmu_index(env, false);
    void *host = probe_read(env, vaddr, CHERI_CAP_SIZE, mmu_idx, retpc);
    if (likely(host)) {
        // Fast path, host address in TLB
#if TARGET_LONG_BITS == 32
#define ld_cap_word_p ldl_p
#elif TARGET_LONG_BITS == 64
#define ld_cap_word_p ldq_p
#else
#error "Unhandled target long width"
#endif
        *pesbt = ld_cap_word_p((char *)host + CHERI_MEM_OFFSET_METADATA);
        *cursor = ld_cap_word_p((char *)host + CHERI_MEM_OFFSET_CURSOR);
#undef ld_cap_word_p
    } else {
        // Slow path for e.g. IO regions.
        qemu_maybe_log_instr_extra(env, "Using slow path for load from guest "
            "address " TARGET_FMT_lx "\n", vaddr);
        *pesbt = cpu_ld_cap_word_ra(env, vaddr + CHERI_MEM_OFFSET_METADATA, retpc);
        *cursor = cpu_ld_cap_word_ra(env, vaddr + CHERI_MEM_OFFSET_CURSOR, retpc);
    }

}

static target_ulong load_tweak_raw(CPUArchState *env, const uintptr_t retpc, const cap_register_t *cb, const target_ulong checked_addr, uint64_t offsel){
    target_ulong pesbt;
    target_ulong cursor;
    load_sig_from_memory_raw(env, &pesbt, &cursor, CHERI_EXC_REGNUM_DDC, cb, checked_addr,
                                        retpc);
    // printf("load_tweak_raw: pesbt = %016lx, cursor = %016lx\n", pesbt, cursor);
    
    target_ulong keyl, keyh;
    get_key_examine_priv(env, env->priv == 0 ? 1 : 0, &keyl, &keyh);

    target_ulong result;
    pesbt = qarma64_dec(pesbt, checked_addr + CHERI_MEM_OFFSET_METADATA, keyl, keyh, 7);
    cursor = qarma64_dec(cursor, checked_addr + CHERI_MEM_OFFSET_CURSOR, keyl, keyh, 7);
    // printf("load_tweak_raw: pesbt tweak = %016lx, cursor tweak = %016lx\n", checked_addr + CHERI_MEM_OFFSET_METADATA, checked_addr + CHERI_MEM_OFFSET_CURSOR);
    // printf("load_tweak_raw: dec pesbt = %016lx, dec cursor = %016lx\n", pesbt, cursor);
    if((pesbt & (target_ulong)0xffffffff) != pesbt){
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    }
    if((cursor & (target_ulong)0xffffffff) != cursor){
        riscv_raise_exception(env, RISCV_EXCP_ILLEGAL_INST, GETPC());
    }
    result = (cursor << (CHERI_MEM_OFFSET_CURSOR * 4)) | (pesbt << (CHERI_MEM_OFFSET_METADATA * 4));
    // printf("load_tweak_raw: result = %016lx\n", result);
    set_off(env, offsel, result);
    return result;
}

target_ulong HELPER(load_tweak_via_ddc)(CPUArchState *env, target_ulong addr, uint64_t offsel){
    GET_HOST_RETPC();
    const cap_register_t *ddc = cheri_get_ddc(env);
    const target_ulong checked_addr =
        cap_check_common_reg(perms_for_load(), env, CHERI_EXC_REGNUM_DDC,
                             cheri_ddc_relative_addr(env, addr),
                             CHERI_CAP_SIZE, _host_return_address, ddc,
                             CHERI_CAP_SIZE, raise_unaligned_load_exception);

    return load_tweak_raw(env, _host_return_address, ddc, checked_addr, offsel);
}

target_ulong HELPER(load_tweak_via_cap)(CPUArchState *env, target_ulong addr, uint32_t authreg, uint64_t offsel){
    GET_HOST_RETPC();
    const cap_register_t *cbp = get_capreg_or_special(env, authreg);
    const target_ulong checked_addr =
        cap_check_common_reg(perms_for_load(), env, authreg,
                             cheri_ddc_relative_addr(env, addr),
                             CHERI_CAP_SIZE, _host_return_address, cbp,
                             CHERI_CAP_SIZE, raise_unaligned_load_exception);

    return load_tweak_raw(env, _host_return_address, cbp, checked_addr, offsel);
}

static void store_sig_to_memory_raw(CPUArchState *env, target_ulong pesbt, target_ulong cursor, target_ulong vaddr, uintptr_t retpc){
    int mmu_idx = cpu_mmu_index(env, false);
    
    env->statcounters_cap_write++;
    void *host = NULL;
    host = cheri_tag_invalidate_aligned(env, vaddr, retpc, mmu_idx);
    if (likely(host)) {
#if TARGET_LONG_BITS == 32
#define st_cap_word_p stl_p
#elif TARGET_LONG_BITS == 64
#define st_cap_word_p stq_p
#else
#error "Unhandled target long width"
#endif
        // Fast path, host address in TLB
        st_cap_word_p((char*)host + CHERI_MEM_OFFSET_METADATA, pesbt);
        st_cap_word_p((char*)host + CHERI_MEM_OFFSET_CURSOR, cursor);
#undef st_cap_word_p
    } else {
        // Slow path for e.g. IO regions.
        qemu_maybe_log_instr_extra(env, "Using slow path for store to guest "
            "address " TARGET_FMT_lx "\n", vaddr);
        cpu_st_cap_word_ra(env, vaddr + CHERI_MEM_OFFSET_METADATA,
                           pesbt, retpc);
        cpu_st_cap_word_ra(env, vaddr + CHERI_MEM_OFFSET_CURSOR, cursor,
                           retpc);
    }
}

static void store_tweak_raw(CPUArchState *env, const uintptr_t retpc, const target_ulong checked_addr, target_ulong value){
    target_ulong pesbt = (value >> (CHERI_MEM_OFFSET_METADATA * 4)) & 0xffffffff;
    target_ulong cursor = (value >> (CHERI_MEM_OFFSET_CURSOR * 4)) & 0xffffffff;
    // printf("store_tweak_raw: result = %016lx\n", value);
    // printf("store_tweak_raw: pesbt = %016lx, cursor = %016lx\n", pesbt, cursor);

    target_ulong keyl, keyh;
    get_key_examine_priv(env, env->priv == 0 ? 1 : 0, &keyl, &keyh);

    pesbt = qarma64_enc(pesbt, checked_addr + CHERI_MEM_OFFSET_METADATA, keyl, keyh, 7);
    cursor = qarma64_enc(cursor, checked_addr + CHERI_MEM_OFFSET_CURSOR, keyl, keyh, 7);
    // printf("store_tweak_raw: pesbt tweak = %016lx, cursor tweak = %016lx\n", checked_addr + CHERI_MEM_OFFSET_METADATA, checked_addr + CHERI_MEM_OFFSET_CURSOR);
    // printf("store_tweak_raw: enc pesbt = %016lx, enc cursor = %016lx\n", pesbt, cursor);

    store_sig_to_memory_raw(env, pesbt, cursor, checked_addr, retpc);
}

void HELPER(store_tweak_via_ddc)(CPUArchState *env, target_ulong addr, target_ulong value){
    GET_HOST_RETPC();
    const cap_register_t *ddc = cheri_get_ddc(env);
    const target_ulong checked_addr =
        cap_check_common_reg(CAP_PERM_STORE, env, CHERI_EXC_REGNUM_DDC,
                             cheri_ddc_relative_addr(env, addr),
                             CHERI_CAP_SIZE, _host_return_address, ddc,
                             CHERI_CAP_SIZE, raise_unaligned_store_exception);

    store_tweak_raw(env, _host_return_address, checked_addr, value);
}

void HELPER(store_tweak_via_cap)(CPUArchState *env, target_ulong addr, uint32_t authreg, target_ulong value){
    GET_HOST_RETPC();
    const cap_register_t *cbp = get_capreg_or_special(env, authreg);
    const target_ulong checked_addr =
        cap_check_common_reg(CAP_PERM_STORE, env, authreg,
                             cheri_ddc_relative_addr(env, addr),
                             CHERI_CAP_SIZE, _host_return_address, cbp,
                             CHERI_CAP_SIZE, raise_unaligned_store_exception);

    store_tweak_raw(env, _host_return_address, checked_addr, value);
}

static void load_sig_raw(CPUArchState *env, const uintptr_t retpc, uint32_t cd, const cap_register_t *cb, const target_ulong checked_addr, uint64_t offsel){
    target_ulong pesbt;
    target_ulong cursor;
    load_sig_from_memory_raw(env, &pesbt, &cursor, CHERI_EXC_REGNUM_DDC, cb, checked_addr,
                                        retpc);
    // printf("load_sig_raw: pesbt = %016lx, cursor = %016lx\n", pesbt, cursor);
    
    target_ulong keyl, keyh;
    get_key_examine_priv(env, env->priv == 0 ? 1 : 0, &keyl, &keyh);

    target_ulong tweak = (checked_addr + get_off(env, offsel)) ^ pesbt;
    // printf("load_sig_raw: addr = %016lx, tweakoff = %016lx\n", checked_addr, get_off(env, offsel));
    cursor = qarma64_dec(cursor, tweak, keyl, keyh, 7);
    // printf("load_sig_raw: tweak = %016lx\n", tweak);
    pesbt = pesbt ^ CAP_NULL_XOR_MASK;
    target_ulong high = cursor >> 39;
    bool tag = (high == 0) || (~high == 0); 
    update_compressed_capreg(env, cd, pesbt, tag, cursor);
}

void HELPER(load_sig_via_ddc)(CPUArchState *env, uint32_t destreg, target_ulong addr, uint64_t offsel){
    GET_HOST_RETPC();
    const cap_register_t *ddc = cheri_get_ddc(env);
    const target_ulong checked_addr =
        cap_check_common_reg(perms_for_load(), env, CHERI_EXC_REGNUM_DDC,
                             cheri_ddc_relative_addr(env, addr),
                             CHERI_CAP_SIZE, _host_return_address, ddc,
                             CHERI_CAP_SIZE, raise_unaligned_load_exception);

    load_sig_raw(env, _host_return_address, destreg, ddc, checked_addr, offsel);
}

void HELPER(load_sig_via_cap)(CPUArchState *env, uint32_t destreg, target_ulong addr, uint32_t authreg, uint64_t offsel){
    GET_HOST_RETPC();
    const cap_register_t *cbp = get_capreg_or_special(env, authreg);
    const target_ulong checked_addr =
        cap_check_common_reg(perms_for_load(), env, authreg,
                             cheri_ddc_relative_addr(env, addr),
                             CHERI_CAP_SIZE, _host_return_address, cbp,
                             CHERI_CAP_SIZE, raise_unaligned_load_exception);

    load_sig_raw(env, _host_return_address, destreg, cbp, checked_addr, offsel);
}

static void store_sig_raw(CPUArchState *env, const uintptr_t retpc, uint32_t srcreg, const target_ulong checked_addr, uint64_t offsel){
    target_ulong cursor = get_capreg_cursor(env, srcreg);
    target_ulong pesbt = get_capreg_pesbt(env, srcreg) ^ CAP_NULL_XOR_MASK;

    target_ulong keyl, keyh;
    get_key_examine_priv(env, env->priv == 0 ? 1 : 0, &keyl, &keyh);

    target_ulong tweak = (checked_addr + get_off(env, offsel)) ^ pesbt;
    cursor = qarma64_enc(cursor, tweak, keyl, keyh, 7);

    store_sig_to_memory_raw(env, pesbt, cursor, checked_addr, retpc);
}

void HELPER(store_sig_via_ddc)(CPUArchState *env, uint32_t srcreg, target_ulong addr, uint64_t offsel){
    GET_HOST_RETPC();
    const cap_register_t *ddc = cheri_get_ddc(env);
    const target_ulong checked_addr =
        cap_check_common_reg(perms_for_store(env, srcreg), env, CHERI_EXC_REGNUM_DDC,
                             cheri_ddc_relative_addr(env, addr),
                             CHERI_CAP_SIZE, _host_return_address, ddc,
                             CHERI_CAP_SIZE, raise_unaligned_store_exception);

    store_sig_raw(env, _host_return_address, srcreg, checked_addr, offsel);
}

void HELPER(store_sig_via_cap)(CPUArchState *env, uint32_t srcreg, target_ulong addr, uint32_t authreg, uint64_t offsel){
    GET_HOST_RETPC();
    const cap_register_t *cbp = get_capreg_or_special(env, authreg);
    const target_ulong checked_addr =
        cap_check_common_reg(perms_for_store(env, srcreg), env, authreg,
                             cheri_ddc_relative_addr(env, addr),
                             CHERI_CAP_SIZE, _host_return_address, cbp,
                             CHERI_CAP_SIZE, raise_unaligned_store_exception);

    store_sig_raw(env, _host_return_address, srcreg, checked_addr, offsel);
}





